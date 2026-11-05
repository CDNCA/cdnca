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
func TestClouDNSProviderVerifier(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "accepted", status: http.StatusOK, body: `{"status":"Success","statusDescription":"Success login."}`},
		{name: "rejected", status: http.StatusOK,
			body: `{"status":"Failed","statusDescription":"Invalid authentication, incorrect sub-auth-id, sub-auth-user or auth-password."}`,
			want: ErrProviderCredentialsRejected},
		{name: "rate limited", status: http.StatusOK,
			body: `{"status":"Failed","statusDescription":"Request blocked. 198.51.100.7 is sending more than 20 requests per second."}`,
			want: ErrProviderVerificationRateLimited},
		{name: "other failure", status: http.StatusOK, body: `{"status":"Failed","statusDescription":"x"}`,
			want: ErrProviderVerificationInvalidResponse},
		{name: "not json", status: http.StatusOK, body: `ok`, want: ErrProviderVerificationInvalidResponse},
		{name: "unavailable", status: http.StatusBadGateway, body: ``, want: ErrProviderVerificationUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/login/login.json" || r.Host != clouDNSVerifyHost ||
					r.URL.RawQuery != "" || r.PostFormValue("sub-auth-id") != "4321" || r.PostFormValue("auth-password") != "fixture-password" {
					t.Errorf("request %s %s host=%s", r.Method, r.URL.Path, r.Host)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verifier := newClouDNSProviderVerifier(server.URL+"/login/login.json", server.Client(), time.Second)
			err := verifier.Verify(context.Background(), "4321", "fixture-password")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestClouDNSCredentialSchema(t *testing.T) {
	if !validProviderCredentialSchema("cloudns", map[string]string{"sub_auth_id": "4321", "auth_password": "p@ss"}) {
		t.Fatal("valid ClouDNS credentials refused")
	}
	for _, bad := range []map[string]string{
		{"sub_auth_id": "4321"},
		{"sub_auth_id": "user", "auth_password": "p"},
		{"sub_auth_id": "1", "auth_password": "has space"},
		{"sub_auth_id": "1", "auth_password": "p", "auth_id": "2"},
	} {
		if validProviderCredentialSchema("cloudns", bad) {
			t.Fatalf("invalid credentials accepted: %v", bad)
		}
	}
	if !supportedProvider("cloudns") || PlatformMinTTLFor("cloudns") != 60 {
		t.Fatal("cloudns not supported or TTL floor wrong")
	}
	if err := NewProviderVerifierDispatcher().VerifyCredentials(context.Background(), "cloudns",
		map[string]string{"sub_auth_id": "1"}); !errors.Is(err, ErrProviderCredentialsInvalid) {
		t.Fatalf("dispatcher with incomplete credentials = %v", err)
	}
}
