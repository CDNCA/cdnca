package gatewayregistry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestNormalizeTrustedProxies(t *testing.T) {
	got, err := normalizeTrustedProxies([]TrustedProxy{{CIDR: " 173.245.48.1/20 ", Header: "cf-connecting-ip"}, {CIDR: "2400:cb00::/32"}})
	if err != nil || got[0] != (TrustedProxy{CIDR: "173.245.48.0/20", Header: "Cf-Connecting-Ip"}) ||
		got[1] != (TrustedProxy{CIDR: "2400:cb00::/32", Header: "X-Forwarded-For"}) {
		t.Fatalf("got %+v %v", got, err)
	}
	for name, items := range map[string][]TrustedProxy{
		"not a cidr":   {{CIDR: "10.0.0.1"}},
		"bad header":   {{CIDR: "10.0.0.0/8", Header: "X Forwarded"}},
		"header colon": {{CIDR: "10.0.0.0/8", Header: "X:Y"}},
		"duplicate":    {{CIDR: "10.0.0.0/8"}, {CIDR: "10.1.0.0/8"}},
	} {
		if _, err := normalizeTrustedProxies(items); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := normalizeTrustedProxies(make([]TrustedProxy, MaxTrustedProxies+1)); !errors.Is(err, ErrInvalidInput) {
		t.Error("oversized list accepted")
	}
}

func TestNormalizeEntrypoints(t *testing.T) {
	got, err := normalizeEntrypoints([]Entrypoint{
		{Address: "CDN.Example.com:443", ServerName: "gw.example.com", Transport: "ws", TunnelHost: "cdn.example.com"},
		{Address: "[2001:db8::1]:21444", ServerName: "gw.example.com", Transport: "grpc"},
	})
	if err != nil || got[0].Address != "cdn.example.com:443" || got[1].Address != "[2001:db8::1]:21444" {
		t.Fatalf("got %+v %v", got, err)
	}
	for name, item := range map[string]Entrypoint{
		"no port":          {Address: "gw.example.com", ServerName: "gw.example.com", Transport: "grpc"},
		"bad transport":    {Address: "gw.example.com:1", ServerName: "gw.example.com", Transport: "tcp"},
		"grpc tunnel host": {Address: "gw.example.com:1", ServerName: "gw.example.com", Transport: "grpc", TunnelHost: "x.example.com"},
		"bad server name":  {Address: "gw.example.com:1", ServerName: "gw", Transport: "grpc"},
		"port zero":        {Address: "gw.example.com:0", ServerName: "gw.example.com", Transport: "grpc"},
	} {
		if _, err := normalizeEntrypoints([]Entrypoint{item}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s accepted", name)
		}
	}
	dup := Entrypoint{Address: "gw.example.com:1", ServerName: "gw.example.com", Transport: "grpc"}
	if _, err := normalizeEntrypoints([]Entrypoint{dup, dup}); !errors.Is(err, ErrInvalidInput) {
		t.Error("duplicate address accepted")
	}
}

func TestNormalizeAllowedIPs(t *testing.T) {
	got, err := normalizeAllowedIPs([]string{" 203.0.113.9 ", "::ffff:198.51.100.1", "2001:DB8::1"})
	if err != nil || got[0] != "203.0.113.9" || got[1] != "198.51.100.1" || got[2] != "2001:db8::1" {
		t.Fatalf("got %v %v", got, err)
	}
	for name, items := range map[string][]string{
		"empty": {}, "range": {"10.0.0.0/8"}, "unspecified": {"0.0.0.0"}, "zone": {"fe80::1%eth0"},
		"duplicate": {"10.0.0.1", "::ffff:10.0.0.1"}, "name": {"gw.example.com"},
	} {
		if _, err := normalizeAllowedIPs(items); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEndpointsVersionFollowsTheList(t *testing.T) {
	a := []Entrypoint{{Address: "a.example.com:1", ServerName: "a.example.com", Transport: "grpc"}}
	b := []Entrypoint{{Address: "a.example.com:1", ServerName: "a.example.com", Transport: "ws"}}
	if EndpointsVersion(nil) != "" || EndpointsVersion(a) == EndpointsVersion(b) || EndpointsVersion(a) != EndpointsVersion(append([]Entrypoint(nil), a...)) {
		t.Fatal("version does not follow the list")
	}
}

// K1: online standalone Gateways, then the co-located Gateway of an
// all/control installation, then the page-edited extra entry points; an extra
// entry repeating an earlier address is dropped.
func TestPublishedEndpointsOrderIncludesTheLocalGateway(t *testing.T) {
	standalone := []Entrypoint{{Address: "gw2.example.com:21444", ServerName: "gw2.example.com", Transport: TransportGRPC, EnrollmentAddress: "gw2.example.com:21443"}}
	local := Entrypoint{Address: "control.example.com:9444", ServerName: "control.example.com", Transport: TransportGRPC, EnrollmentAddress: "control.example.com:9443"}
	extra := []Entrypoint{
		{Address: "control.example.com:9444", ServerName: "control.example.com", Transport: TransportGRPC},
		{Address: "cdn.example.com:443", ServerName: "control.example.com", Transport: TransportWS, TunnelHost: "cdn.example.com"},
	}
	got := publishedEndpoints(standalone, local, extra)
	if len(got) != 3 || got[0] != standalone[0] || got[1] != local || got[2] != extra[1] {
		t.Fatalf("got %+v", got)
	}
	// Standalone Gateway disabled: nodes migrate to the local Gateway.
	if got := publishedEndpoints(nil, local, nil); len(got) != 1 || got[0] != local {
		t.Fatalf("without standalone = %+v", got)
	}
	// No local Gateway configured: unchanged behaviour.
	if got := publishedEndpoints(standalone, Entrypoint{}, extra); len(got) != 3 || got[1] != extra[0] {
		t.Fatalf("without local = %+v", got)
	}
}

func TestLocalGatewayEndpoint(t *testing.T) {
	got, err := LocalGatewayEndpoint("Control.Example.com:9444", "control.example.com", "control.example.com:9443")
	if err != nil || got != (Entrypoint{Address: "control.example.com:9444", ServerName: "control.example.com", Transport: TransportGRPC,
		EnrollmentAddress: "control.example.com:9443"}) {
		t.Fatalf("got %+v %v", got, err)
	}
	if got, err := LocalGatewayEndpoint("[2001:db8::1]:9444", "2001:db8::1", "[2001:db8::1]:9443"); err != nil || got.Address != "[2001:db8::1]:9444" {
		t.Fatalf("ipv6 = %+v %v", got, err)
	}
	if got, err := LocalGatewayEndpoint("", "", ""); err != nil || got != (Entrypoint{}) {
		t.Fatalf("unset = %+v %v", got, err)
	}
	for name, args := range map[string][3]string{
		"partial":         {"control.example.com:9444", "", ""},
		"no port":         {"control.example.com", "control.example.com", "control.example.com:9443"},
		"bad enrollment":  {"control.example.com:9444", "control.example.com", "control.example.com"},
		"bad server name": {"control.example.com:9444", "control", "control.example.com:9443"},
	} {
		if _, err := LocalGatewayEndpoint(args[0], args[1], args[2]); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSettingsETagFollowsTheContent(t *testing.T) {
	base := Settings{TrustedProxies: []TrustedProxy{{CIDR: "10.0.0.0/8", Header: "X-Real-Ip"}}, Entrypoints: []Entrypoint{}}
	same := Settings{TrustedProxies: []TrustedProxy{{CIDR: "10.0.0.0/8", Header: "X-Real-Ip"}}, Entrypoints: []Entrypoint{}}
	changed := Settings{TrustedProxies: []TrustedProxy{{CIDR: "10.0.0.0/8", Header: "X-Forwarded-For"}}, Entrypoints: []Entrypoint{}}
	etag := SettingsETag(base)
	if etag != SettingsETag(same) || etag == SettingsETag(changed) || !regexp.MustCompile(`^"sha256-[0-9a-f]{64}"$`).MatchString(etag) {
		t.Fatalf("etag = %s", etag)
	}
}

// G1: PUT without If-Match is refused before the body or the database is touched.
func TestUpdateSettingsRequiresIfMatch(t *testing.T) {
	signer := Signer{Client: testCA(t, "client"), Server: testCA(t, "root")}
	service := &Service{config: Config{Signer: signer, Now: time.Now}, rootFingerprint: RootFingerprint(signer.Server.Certificate.Raw)}
	handler, err := NewHandler(service, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(),
			ScopeKind: "platform", Permissions: []string{PermissionManage}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{nil, {""}, {`"a"`, `"b"`}} {
		request := httptest.NewRequest(http.MethodPut, "/v1/admin/gateway-settings", strings.NewReader(`{"trusted_proxies":[],"entrypoints":[]}`))
		request.Header.Set("Authorization", "Bearer token")
		request.Header.Set("Content-Type", "application/json")
		for _, value := range values {
			request.Header.Add("If-Match", value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusPreconditionRequired || !strings.Contains(response.Body.String(), "precondition_required") {
			t.Errorf("If-Match %q = %d %s", values, response.Code, response.Body.String())
		}
	}
}
