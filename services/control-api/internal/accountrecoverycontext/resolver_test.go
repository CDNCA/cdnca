package accountrecoverycontext

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	testTenantA = uuid.MustParse("018f47d2-843d-7ad1-a769-cccf3f448d80")
	testScopeA  = uuid.MustParse("018f47d2-843d-7ad1-a769-cccf3f448d81")
	testTenantB = uuid.MustParse("018f47d2-843d-7ad1-a769-cccf3f448d82")
	testScopeB  = uuid.MustParse("018f47d2-843d-7ad1-a769-cccf3f448d83")
)

type queryResult struct {
	count    int64
	tenantID string
	scopeID  string
	hostname string
	err      error
}

type fakeQueryRower struct {
	results map[string]queryResult
	result  queryResult
	calls   int
	query   string
	args    []any
}

func (database *fakeQueryRower) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	database.calls++
	database.query = query
	database.args = append([]any(nil), args...)
	result := database.result
	if database.results != nil && len(args) == 1 {
		result = database.results[args[0].(string)]
	}
	return fakeRow{result: result}
}

type fakeRow struct {
	result queryResult
}

func (row fakeRow) Scan(destinations ...any) error {
	if row.result.err != nil {
		return row.result.err
	}
	if len(destinations) != 4 {
		return errors.New("unexpected scan shape")
	}
	*destinations[0].(*int64) = row.result.count
	*destinations[1].(*string) = row.result.tenantID
	*destinations[2].(*string) = row.result.scopeID
	*destinations[3].(*string) = row.result.hostname
	return nil
}

func TestResolveSelectsTenantOnlyByCanonicalHost(t *testing.T) {
	database := &fakeQueryRower{results: map[string]queryResult{
		"a.recovery.example": bindingResult(testTenantA, testScopeA, "a.recovery.example"),
		"b.recovery.example": bindingResult(testTenantB, testScopeB, "b.recovery.example"),
	}}
	resolver := newTestResolver(t, database, Config{})

	for _, test := range []struct {
		host     string
		tenantID uuid.UUID
		scopeID  uuid.UUID
	}{
		{host: "a.recovery.example", tenantID: testTenantA, scopeID: testScopeA},
		{host: "b.recovery.example", tenantID: testTenantB, scopeID: testScopeB},
	} {
		request := newRequest(test.host, "198.51.100.10:42000")
		request.Header.Set("X-Tenant", testTenantB.String())
		request.Header.Set("X-Scope", testScopeB.String())
		request.Header.Set("Cookie", "tenant="+testTenantB.String())
		request.Header.Set("Authorization", "Bearer "+testTenantB.String())
		request.Header.Set("X-API-Key", testScopeB.String())
		request.Header.Set("Host", "header-spoof.recovery.example")
		request.Body = io.NopCloser(strings.NewReader(`{"username":"shared-user"}`))

		trusted, err := resolver.Resolve(request)
		if err != nil {
			t.Fatalf("resolve %s: %v", test.host, err)
		}
		if trusted.TenantID != test.tenantID || trusted.ScopeID != test.scopeID ||
			trusted.SourceIP != "198.51.100.10" {
			t.Fatalf("trusted context for %s = %+v", test.host, trusted)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != `{"username":"shared-user"}` {
			t.Fatalf("resolver consumed shared username body: %q, %v", body, err)
		}
	}
	if database.calls != 2 || len(database.args) != 1 || database.args[0] != "b.recovery.example" {
		t.Fatalf("database calls=%d args=%v", database.calls, database.args)
	}
	if strings.Contains(database.query, ";") || !strings.Contains(database.query, "JOIN access_scopes") ||
		!strings.Contains(database.query, "tenant.status = 'active'") {
		t.Fatalf("binding query is not one active-scope statement: %q", database.query)
	}
}

func TestResolveCanonicalizesDirectIPv6(t *testing.T) {
	database := singleBindingDatabase("ipv6.recovery.example", testTenantA, testScopeA)
	resolver := newTestResolver(t, database, Config{})
	trusted, err := resolver.Resolve(newRequest("ipv6.recovery.example", "[2001:0db8:0000::20]:443"))
	if err != nil || trusted.SourceIP != "2001:db8::20" {
		t.Fatalf("trusted=%+v err=%v", trusted, err)
	}
}

func TestResolveSelectsExplicitPlatformHost(t *testing.T) {
	database := &fakeQueryRower{result: queryResult{
		count: 1, scopeID: testScopeA.String(), hostname: "203.0.113.73",
	}}
	resolver := newTestResolver(t, database, Config{PlatformHosts: []string{"203.0.113.73"}})
	trusted, err := resolver.Resolve(newRequest("203.0.113.73", "198.51.100.10:443"))
	if err != nil || trusted.TenantID != uuid.Nil || trusted.ScopeID != testScopeA ||
		trusted.SourceIP != "198.51.100.10" {
		t.Fatalf("platform trusted context=%+v err=%v", trusted, err)
	}
	if database.calls != 1 || database.args[0] != "203.0.113.73" ||
		!strings.Contains(database.query, "role.name = 'platform_owner'") {
		t.Fatalf("platform query calls=%d args=%v query=%q", database.calls, database.args, database.query)
	}
}

func TestResolveRejectsUnlistedPlatformIP(t *testing.T) {
	database := &fakeQueryRower{}
	resolver := newTestResolver(t, database, Config{})
	if _, err := resolver.Resolve(newRequest("203.0.113.73", "198.51.100.10:443")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unlisted platform IP error=%v", err)
	}
	if database.calls != 0 {
		t.Fatal("unlisted platform IP reached database")
	}
}

func TestResolveIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	database := singleBindingDatabase("direct.recovery.example", testTenantA, testScopeA)
	resolver := newTestResolver(t, database, Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	request := newRequest("direct.recovery.example", "198.51.100.11:44321")
	request.Header.Set("Forwarded", `for=203.0.113.90;host=other.recovery.example`)
	request.Header.Set("X-Forwarded-For", "203.0.113.91")
	request.Header.Set("X-Forwarded-Host", "other.recovery.example")

	trusted, err := resolver.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.SourceIP != "198.51.100.11" || database.args[0] != "direct.recovery.example" {
		t.Fatalf("untrusted forwarding changed context: trusted=%+v args=%v", trusted, database.args)
	}
}

func TestResolveTrustedProxyChains(t *testing.T) {
	tests := []struct {
		name       string
		forwarded  string
		xff        string
		xfh        string
		host       string
		wantHost   string
		wantSource string
	}{
		{
			name:      "forwarded ipv4 multi hop",
			forwarded: `for=198.51.100.20, for=10.1.0.8;host=forwarded.recovery.example`,
			host:      "direct.recovery.example", wantHost: "forwarded.recovery.example", wantSource: "198.51.100.20",
		},
		{
			name: "xff ipv6 multi hop", xff: "2001:db8::20, 10.1.0.8",
			xfh: "forwarded.recovery.example", host: "direct.recovery.example",
			wantHost: "forwarded.recovery.example", wantSource: "2001:db8::20",
		},
		{
			name: "rightmost untrusted wins", xff: "203.0.113.40, 198.51.100.40, 10.1.0.8",
			host: "direct.recovery.example", wantHost: "direct.recovery.example", wantSource: "198.51.100.40",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := singleBindingDatabase(test.wantHost, testTenantA, testScopeA)
			resolver := newTestResolver(t, database, Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
			request := newRequest(test.host, "10.1.0.9:443")
			setHeader(request, "Forwarded", test.forwarded)
			setHeader(request, "X-Forwarded-For", test.xff)
			setHeader(request, "X-Forwarded-Host", test.xfh)
			trusted, err := resolver.Resolve(request)
			if err != nil {
				t.Fatal(err)
			}
			if trusted.SourceIP != test.wantSource || database.args[0] != test.wantHost {
				t.Fatalf("trusted=%+v query args=%v", trusted, database.args)
			}
		})
	}
}

func TestResolveRejectsAmbiguousOrInvalidTrustedProxyInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "forwarded and xff conflict", mutate: func(request *http.Request) {
			request.Header.Set("Forwarded", "for=198.51.100.20")
			request.Header.Set("X-Forwarded-For", "198.51.100.20")
		}},
		{name: "forwarded and xfh host conflict", mutate: func(request *http.Request) {
			request.Header.Set("Forwarded", `for=198.51.100.20;host=a.recovery.example`)
			request.Header.Set("X-Forwarded-Host", "a.recovery.example")
		}},
		{name: "duplicate forwarded header", mutate: func(request *http.Request) {
			request.Header.Add("Forwarded", "for=198.51.100.20")
			request.Header.Add("Forwarded", "for=198.51.100.21")
		}},
		{name: "duplicate xff header", mutate: func(request *http.Request) {
			request.Header.Add("X-Forwarded-For", "198.51.100.20")
			request.Header.Add("X-Forwarded-For", "198.51.100.21")
		}},
		{name: "unknown forwarded for", mutate: func(request *http.Request) {
			request.Header.Set("Forwarded", "for=unknown")
		}},
		{name: "obfuscated forwarded for", mutate: func(request *http.Request) {
			request.Header.Set("Forwarded", "for=_hidden")
		}},
		{name: "forwarded port ambiguity", mutate: func(request *http.Request) {
			request.Header.Set("Forwarded", `for="198.51.100.20:443"`)
		}},
		{name: "xff port ambiguity", mutate: func(request *http.Request) {
			request.Header.Set("X-Forwarded-For", "198.51.100.20:443")
		}},
		{name: "private client", mutate: func(request *http.Request) {
			request.Header.Set("X-Forwarded-For", "192.168.4.2, 10.1.0.8")
		}},
		{name: "loopback client", mutate: func(request *http.Request) {
			request.Header.Set("X-Forwarded-For", "127.0.0.1, 10.1.0.8")
		}},
		{name: "too many hops", mutate: func(request *http.Request) {
			request.Header.Set("X-Forwarded-For", strings.Repeat("198.51.100.20,", 16)+"198.51.100.21")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := singleBindingDatabase("a.recovery.example", testTenantA, testScopeA)
			resolver := newTestResolver(t, database, Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
			request := newRequest("a.recovery.example", "10.1.0.9:443")
			test.mutate(request)
			if _, err := resolver.Resolve(request); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error=%v", err)
			}
			if database.calls != 0 {
				t.Fatalf("invalid proxy input reached database: %d calls", database.calls)
			}
		})
	}
}

func TestResolvePrivateSourcePolicyIsExplicit(t *testing.T) {
	database := singleBindingDatabase("a.recovery.example", testTenantA, testScopeA)
	resolver := newTestResolver(t, database, Config{
		TrustedProxyCIDRs: []string{"10.0.0.0/8"}, AllowPrivateSourceIP: true,
	})
	request := newRequest("a.recovery.example", "10.1.0.9:443")
	request.Header.Set("X-Forwarded-For", "192.168.4.2, 10.1.0.8")
	trusted, err := resolver.Resolve(request)
	if err != nil || trusted.SourceIP != "192.168.4.2" {
		t.Fatalf("trusted=%+v err=%v", trusted, err)
	}
}

func TestResolveRejectsPrivateDirectPeerAndTrustedPeerWithoutChain(t *testing.T) {
	for _, test := range []struct {
		name   string
		config Config
	}{
		{name: "private direct"},
		{name: "trusted peer missing chain", config: Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := singleBindingDatabase("a.recovery.example", testTenantA, testScopeA)
			resolver := newTestResolver(t, database, test.config)
			if _, err := resolver.Resolve(newRequest("a.recovery.example", "10.1.0.9:443")); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error=%v", err)
			}
			if database.calls != 0 {
				t.Fatal("invalid private boundary reached database")
			}
		})
	}
}

func TestResolveHostCanonicalAndPunycodePolicy(t *testing.T) {
	valid := []string{"a.example", "xn--bcher-kva.example", "a-b.example"}
	for _, hostname := range valid {
		t.Run("valid "+hostname, func(t *testing.T) {
			database := singleBindingDatabase(hostname, testTenantA, testScopeA)
			resolver := newTestResolver(t, database, Config{})
			if _, err := resolver.Resolve(newRequest(hostname, "198.51.100.10:443")); err != nil {
				t.Fatal(err)
			}
		})
	}
	invalid := []string{
		"A.example", "a.example.", "a.example:443", "*.example", "192.0.2.1", "[2001:db8::1]",
		"localhost", "a.localhost", "local", "a.local", "internal", "a.internal", "a\n.example",
		"b\u00fccher.example", "-a.example", "a-.example", strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 126) + "aa",
	}
	for index, hostname := range invalid {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			database := singleBindingDatabase("unused.example", testTenantA, testScopeA)
			resolver := newTestResolver(t, database, Config{})
			if _, err := resolver.Resolve(newRequest(hostname, "198.51.100.10:443")); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("hostname=%q error=%v", hostname, err)
			}
			if database.calls != 0 {
				t.Fatalf("invalid hostname reached database")
			}
		})
	}
}

func TestResolveMetadataCannotBeForgedByHeaders(t *testing.T) {
	database := singleBindingDatabase("a.recovery.example", testTenantA, testScopeA)
	resolver := newTestResolver(t, database, Config{})
	request := newRequest("a.recovery.example", "198.51.100.10:443")
	request.Header.Set("X-Request-ID", "client-request-id")
	request.Header.Set("X-Trace-ID", "client-trace-id")
	first, err := resolver.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID == "client-request-id" || first.TraceID == "client-trace-id" ||
		first.RequestID == second.RequestID || first.TraceID == second.TraceID {
		t.Fatalf("generated metadata first=%+v second=%+v", first, second)
	}
	parsed, err := uuid.Parse(first.RequestID)
	if err != nil || parsed.Version() != 7 || len(first.TraceID) != 32 || first.TraceID != strings.ToLower(first.TraceID) {
		t.Fatalf("request/trace metadata=%q/%q", first.RequestID, first.TraceID)
	}
}

func TestResolveUsesOnlyExplicitTrustedMetadataSource(t *testing.T) {
	type metadataKey struct{}
	database := singleBindingDatabase("a.recovery.example", testTenantA, testScopeA)
	resolver := newTestResolver(t, database, Config{MetadataSource: MetadataSourceFunc(
		func(request *http.Request) (Metadata, error) {
			metadata, _ := request.Context().Value(metadataKey{}).(Metadata)
			return metadata, nil
		},
	)})
	request := newRequest("a.recovery.example", "198.51.100.10:443")
	request.Header.Set("X-Request-ID", "client-request-id")
	request.Header.Set("X-Trace-ID", "client-trace-id")
	request = request.WithContext(context.WithValue(request.Context(), metadataKey{}, Metadata{
		RequestID: "server-request-id", TraceID: "0123456789abcdef0123456789abcdef",
	}))
	trusted, err := resolver.Resolve(request)
	if err != nil || trusted.RequestID != "server-request-id" ||
		trusted.TraceID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("trusted=%+v err=%v", trusted, err)
	}
}

func TestResolveRejectsInvalidTrustedMetadata(t *testing.T) {
	for _, metadata := range []Metadata{
		{RequestID: "client request", TraceID: "0123456789abcdef0123456789abcdef"},
		{RequestID: "server-request", TraceID: strings.Repeat("0", 32)},
		{RequestID: "server-request", TraceID: "UPPER0123456789ABCDEF0123456789A"},
	} {
		database := singleBindingDatabase("a.recovery.example", testTenantA, testScopeA)
		resolver := newTestResolver(t, database, Config{MetadataSource: MetadataSourceFunc(
			func(*http.Request) (Metadata, error) { return metadata, nil },
		)})
		if _, err := resolver.Resolve(newRequest("a.recovery.example", "198.51.100.10:443")); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("metadata=%+v error=%v", metadata, err)
		}
		if database.calls != 0 {
			t.Fatal("invalid metadata reached database")
		}
	}
	database := singleBindingDatabase("a.recovery.example", testTenantA, testScopeA)
	resolver := newTestResolver(t, database, Config{MetadataSource: MetadataSourceFunc(nil)})
	if _, err := resolver.Resolve(newRequest("a.recovery.example", "198.51.100.10:443")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("typed nil metadata source error=%v", err)
	}
}

func TestResolveFailsClosedAndRedactsBindingFailures(t *testing.T) {
	secret := "tenant-secret.example"
	tests := []queryResult{
		{err: errors.New("database password=secret host=" + secret)},
		{},
		{count: 2, tenantID: testTenantA.String(), scopeID: testScopeA.String(), hostname: secret},
		{count: 1, tenantID: "not-a-uuid", scopeID: testScopeA.String(), hostname: secret},
		{count: 1, tenantID: testTenantA.String(), scopeID: uuid.Nil.String(), hostname: secret},
		{count: 1, tenantID: testTenantA.String(), scopeID: testScopeA.String(), hostname: "other.example"},
	}
	for index, result := range tests {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			database := &fakeQueryRower{result: result}
			resolver := newTestResolver(t, database, Config{})
			_, err := resolver.Resolve(newRequest(secret, "198.51.100.10:443"))
			if !errors.Is(err, ErrUnavailable) || err.Error() != ErrUnavailable.Error() ||
				strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "password") {
				t.Fatalf("error=%q", err)
			}
		})
	}
}

func TestNewResolverRejectsInvalidConfiguration(t *testing.T) {
	validDatabase := singleBindingDatabase("a.example", testTenantA, testScopeA)
	tests := []struct {
		name     string
		database QueryRower
		config   Config
	}{
		{name: "nil database"},
		{name: "invalid cidr", database: validDatabase, config: Config{TrustedProxyCIDRs: []string{"10.0.0.1/8"}}},
		{name: "duplicate cidr", database: validDatabase, config: Config{TrustedProxyCIDRs: []string{"10.0.0.0/8", "10.0.0.0/8"}}},
		{name: "all ipv4 cidr", database: validDatabase, config: Config{TrustedProxyCIDRs: []string{"0.0.0.0/0"}}},
		{name: "all ipv6 cidr", database: validDatabase, config: Config{TrustedProxyCIDRs: []string{"::/0"}}},
		{name: "mapped cidr", database: validDatabase, config: Config{TrustedProxyCIDRs: []string{"::ffff:10.0.0.0/104"}}},
		{name: "invalid platform host", database: validDatabase, config: Config{PlatformHosts: []string{"console.local"}}},
		{name: "duplicate platform host", database: validDatabase, config: Config{PlatformHosts: []string{"203.0.113.73", "203.0.113.73"}}},
		{name: "too many hops", database: validDatabase, config: Config{MaxProxyHops: 65}},
		{name: "negative hops", database: validDatabase, config: Config{MaxProxyHops: -1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewResolver(test.database, test.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func newTestResolver(t *testing.T, database QueryRower, config Config) *Resolver {
	t.Helper()
	resolver, err := NewResolver(database, config)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func singleBindingDatabase(hostname string, tenantID, scopeID uuid.UUID) *fakeQueryRower {
	return &fakeQueryRower{results: map[string]queryResult{
		hostname: bindingResult(tenantID, scopeID, hostname),
	}}
}

func bindingResult(tenantID, scopeID uuid.UUID, hostname string) queryResult {
	return queryResult{count: 1, tenantID: tenantID.String(), scopeID: scopeID.String(), hostname: hostname}
}

func newRequest(host, remoteAddress string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://placeholder.invalid/v1/account-recovery/requests", nil)
	request.Host = host
	request.RemoteAddr = remoteAddress
	return request
}

func setHeader(request *http.Request, name, value string) {
	if value != "" {
		request.Header.Set(name, value)
	}
}
