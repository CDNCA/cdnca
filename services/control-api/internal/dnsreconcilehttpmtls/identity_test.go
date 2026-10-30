package dnsreconcilehttpmtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAuthenticatorRequiresOneExactVerifiedURIIdentityAndRejectsBearer(t *testing.T) {
	tenantID := uuid.New()
	siteID := uuid.New()
	allowedURI := "spiffe://cdnca.local/dns-reconcile/provider-a"
	authenticator, err := NewAuthenticator([]Identity{{
		URI: allowedURI, WorkloadID: "provider-a", TenantID: tenantID, SiteID: siteID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"https://control/internal/v1/dns/reconcile/tasks/"+uuid.NewString()+"/provider-reports", nil)
	request.TLS = verifiedTLSState(t, allowedURI)
	principal, err := authenticator.Authenticate(request)
	if err != nil || principal.WorkloadID != "provider-a" || principal.TenantID != tenantID || principal.SiteID != siteID {
		t.Fatalf("principal=(%+v,%v)", principal, err)
	}

	for _, test := range []struct {
		name     string
		uris     []string
		bearer   bool
		verified bool
	}{
		{name: "wrong URI", uris: []string{"spiffe://cdnca.local/dns-reconcile/other"}, verified: true},
		{name: "multiple URI SANs", uris: []string{allowedURI, "spiffe://cdnca.local/dns-reconcile/other"}, verified: true},
		{name: "unverified chain", uris: []string{allowedURI}},
		{name: "bearer forbidden", uris: []string{allowedURI}, verified: true, bearer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rejected := request.Clone(request.Context())
			rejected.TLS = verifiedTLSState(t, test.uris...)
			if !test.verified {
				rejected.TLS.VerifiedChains = nil
			}
			if test.bearer {
				rejected.Header.Set("Authorization", "Bearer tenant-token")
			}
			if _, err := authenticator.Authenticate(rejected); err == nil {
				t.Fatal("request was accepted")
			}
		})
	}
}

func TestAuthenticatorRejectsNilURISANWithoutPanic(t *testing.T) {
	authenticator, err := NewAuthenticator([]Identity{{
		URI: "spiffe://cdnca.local/dns-reconcile/provider-a", WorkloadID: "provider-a",
		TenantID: uuid.New(), SiteID: uuid.New(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"https://control/internal/v1/dns/reconcile/tasks/11111111-1111-4111-8111-111111111111/provider-reports", nil)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
		URIs: []*url.URL{nil},
	}}}}
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("nil URI SAN was accepted")
	}
}

func TestCanonicalWorkloadURIRequiresExactSPIFFEIdentity(t *testing.T) {
	const baselineURI = "spiffe://cdnca.local/dns-reconcile/provider-a"
	tenantID, siteID := uuid.New(), uuid.New()
	maximumTrustDomain := strings.Join([]string{
		strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61),
	}, ".")
	overlongTrustDomain := strings.Join([]string{
		strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 62),
	}, ".")
	if len(maximumTrustDomain) != 253 || len(overlongTrustDomain) != 254 {
		t.Fatal("trust domain boundary fixture has the wrong length")
	}
	baseline, err := NewAuthenticator([]Identity{{
		URI: baselineURI, WorkloadID: "provider-a", TenantID: tenantID, SiteID: siteID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	invalid := []struct {
		name string
		uri  string
	}{
		{name: "uppercase scheme", uri: "SPIFFE://cdnca.local/dns-reconcile/provider-a"},
		{name: "userinfo", uri: "spiffe://user@cdnca.local/dns-reconcile/provider-a"},
		{name: "explicit port", uri: "spiffe://cdnca.local:443/dns-reconcile/provider-a"},
		{name: "empty port", uri: "spiffe://cdnca.local:/dns-reconcile/provider-a"},
		{name: "uppercase trust domain", uri: "spiffe://CDNCA.local/dns-reconcile/provider-a"},
		{name: "IPv4 authority", uri: "spiffe://192.0.2.1/dns-reconcile/provider-a"},
		{name: "IPv6 authority", uri: "spiffe://[2001:db8::1]/dns-reconcile/provider-a"},
		{name: "empty DNS label", uri: "spiffe://cdnca..local/dns-reconcile/provider-a"},
		{name: "leading hyphen label", uri: "spiffe://-cdnca.local/dns-reconcile/provider-a"},
		{name: "trailing hyphen label", uri: "spiffe://cdnca-.local/dns-reconcile/provider-a"},
		{name: "overlong DNS label", uri: "spiffe://" + strings.Repeat("a", 64) + ".local/dns-reconcile/provider-a"},
		{name: "overlong trust domain", uri: "spiffe://" + overlongTrustDomain + "/dns-reconcile/provider-a"},
		{name: "invalid DNS label character", uri: "spiffe://cdn_fly.local/dns-reconcile/provider-a"},
		{name: "missing path", uri: "spiffe://cdnca.local"},
		{name: "dot segment", uri: "spiffe://cdnca.local/dns-reconcile/./provider-a"},
		{name: "dotdot segment", uri: "spiffe://cdnca.local/dns-reconcile/../provider-a"},
		{name: "encoded slash", uri: "spiffe://cdnca.local/dns-reconcile%2Fprovider-a"},
		{name: "encoded dot", uri: "spiffe://cdnca.local/dns-reconcile/%2e/provider-a"},
		{name: "encoded space", uri: "spiffe://cdnca.local/dns-reconcile/provider%20a"},
		{name: "encoded NUL", uri: "spiffe://cdnca.local/dns-reconcile/provider%00a"},
		{name: "double slash", uri: "spiffe://cdnca.local/dns-reconcile//provider-a"},
		{name: "trailing slash", uri: "spiffe://cdnca.local/dns-reconcile/provider-a/"},
		{name: "query", uri: "spiffe://cdnca.local/dns-reconcile/provider-a?mode=write"},
		{name: "fragment", uri: "spiffe://cdnca.local/dns-reconcile/provider-a#fragment"},
		{name: "opaque", uri: "spiffe:cdnca.local/dns-reconcile/provider-a"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if canonical, ok := canonicalWorkloadURI(test.uri); ok || canonical != "" {
				t.Fatalf("canonicalWorkloadURI(%q) = (%q, %t)", test.uri, canonical, ok)
			}
			if _, err := NewAuthenticator([]Identity{{
				URI: test.uri, WorkloadID: "provider-a", TenantID: tenantID, SiteID: siteID,
			}}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewAuthenticator(%q) error = %v", test.uri, err)
			}
			parsed, parseErr := url.Parse(test.uri)
			if parseErr == nil && parsed.String() == test.uri {
				request := httptest.NewRequest(http.MethodPost,
					"https://control/internal/v1/dns/reconcile/tasks/11111111-1111-4111-8111-111111111111/provider-reports", nil)
				request.TLS = verifiedTLSState(t, test.uri)
				if _, err := baseline.Authenticate(request); !errors.Is(err, ErrUnauthenticated) {
					t.Fatalf("Authenticate(%q) error = %v", test.uri, err)
				}
			}
		})
	}

	for _, validURI := range []string{
		baselineURI,
		"spiffe://control-plane.cdnca.local/dns-reconcile/providers/provider-a/worker-1",
		"spiffe://" + maximumTrustDomain + "/dns-reconcile/provider-a",
	} {
		t.Run("valid "+validURI, func(t *testing.T) {
			canonical, ok := canonicalWorkloadURI(validURI)
			if !ok || canonical != validURI {
				t.Fatalf("canonicalWorkloadURI(%q) = (%q, %t)", validURI, canonical, ok)
			}
			authenticator, err := NewAuthenticator([]Identity{{
				URI: validURI, WorkloadID: "provider-a", TenantID: tenantID, SiteID: siteID,
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost,
				"https://control/internal/v1/dns/reconcile/tasks/11111111-1111-4111-8111-111111111111/provider-reports", nil)
			request.TLS = verifiedTLSState(t, validURI)
			principal, err := authenticator.Authenticate(request)
			if err != nil || principal.WorkloadID != "provider-a" || principal.TenantID != tenantID || principal.SiteID != siteID {
				t.Fatalf("Authenticate(%q) = (%+v, %v)", validURI, principal, err)
			}
		})
	}
}

func TestRouteGuardAllowsOnlyProviderReportPOST(t *testing.T) {
	var calls int
	guard := newRouteGuard(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		writer.WriteHeader(http.StatusNoContent)
	}))
	taskID := uuid.NewString()
	allowed := httptest.NewRequest(http.MethodPost,
		"https://control/internal/v1/dns/reconcile/tasks/"+taskID+"/provider-reports", nil)
	allowed.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
	response := httptest.NewRecorder()
	guard.ServeHTTP(response, allowed)
	if response.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("allowed status=%d calls=%d", response.Code, calls)
	}
	for _, target := range []struct{ method, path string }{
		{http.MethodGet, allowed.URL.Path},
		{http.MethodPost, "/v1/sites/" + uuid.NewString() + "/dns-reconcile/apply"},
		{http.MethodPost, allowed.URL.Path + "/extra"},
	} {
		response := httptest.NewRecorder()
		guard.ServeHTTP(response, httptest.NewRequest(target.method, "https://control"+target.path, nil))
		if response.Code == http.StatusNoContent {
			t.Fatalf("accepted %s %s", target.method, target.path)
		}
	}
}

func TestTLSFloorIncludesTLS12AndTLS13Only(t *testing.T) {
	config := tlsVersionConfig()
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS range=%x..%x", config.MinVersion, config.MaxVersion)
	}
}

func verifiedTLSState(t *testing.T, uris ...string) *tls.ConnectionState {
	t.Helper()
	certificate := &x509.Certificate{}
	for _, raw := range uris {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		certificate.URIs = append(certificate.URIs, parsed)
	}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
}
