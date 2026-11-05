package dnsacme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test-only credentials; requests go to the httptest server only.
func TestNamecheapProviderVerifier(t *testing.T) {
	ok := `<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><CommandResponse Type="namecheap.domains.getList"><DomainGetListResult /></CommandResponse></ApiResponse>`
	refused := func(number string) string {
		return `<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response"><Errors><Error Number="` +
			number + `">x</Error></Errors></ApiResponse>`
	}
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "accepted", status: http.StatusOK, body: ok},
		{name: "bad key", status: http.StatusOK, body: refused("1011102"), want: ErrProviderCredentialsRejected},
		{name: "ip not whitelisted", status: http.StatusOK, body: refused("1011150"), want: ErrProviderCredentialsRejected},
		{name: "other error", status: http.StatusOK, body: refused("5050169"), want: ErrProviderVerificationInvalidResponse},
		{name: "not xml", status: http.StatusOK, body: `{}`, want: ErrProviderVerificationInvalidResponse},
		{name: "rate limited", status: http.StatusTooManyRequests, want: ErrProviderVerificationRateLimited},
		{name: "unavailable", status: http.StatusServiceUnavailable, want: ErrProviderVerificationUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/xml.response" || r.Host != namecheapVerifyHost || r.URL.RawQuery != "" ||
					r.PostFormValue("ApiUser") != "fixture-user" || r.PostFormValue("ApiKey") != "fixture-key" ||
					r.PostFormValue("ClientIp") != "192.0.2.44" || r.PostFormValue("Command") != "namecheap.domains.getList" {
					t.Errorf("request %s %s host=%s", r.Method, r.URL.Path, r.Host)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verifier := newNamecheapProviderVerifier(server.URL+"/xml.response", server.Client(), time.Second)
			err := verifier.Verify(context.Background(), "fixture-user", "fixture-key", "192.0.2.44")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNamecheapCredentialSchema(t *testing.T) {
	if !validProviderCredentialSchema("namecheap", map[string]string{"username": "u", "api_key": "k", "source_ip": "192.0.2.1"}) {
		t.Fatal("valid Namecheap credentials refused")
	}
	for _, bad := range []map[string]string{
		{"username": "u", "api_key": "k"},
		{"username": "u", "api_key": "k", "source_ip": "2001:db8::1"},
		{"username": "u", "api_key": "k", "source_ip": "198.51.100"},
		{"username": "u", "api_key": "k k", "source_ip": "192.0.2.1"},
	} {
		if validProviderCredentialSchema("namecheap", bad) {
			t.Fatalf("invalid credentials accepted: %v", bad)
		}
	}
	if !supportedProvider("namecheap") || PlatformMinTTLFor("namecheap") != 60 {
		t.Fatal("namecheap not supported or TTL floor wrong")
	}
	if err := NewProviderVerifierDispatcher().VerifyCredentials(context.Background(), "namecheap",
		map[string]string{"username": "u"}); !errors.Is(err, ErrProviderCredentialsInvalid) {
		t.Fatalf("dispatcher with incomplete credentials = %v", err)
	}
}
