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
func TestNameComProviderVerifier(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "accepted", status: http.StatusOK, body: `{"motd":"m","serverName":"s","serverTime":"t","username":"fixture-user"}`},
		{name: "other user", status: http.StatusOK, body: `{"username":"someone-else"}`, want: ErrProviderVerificationInvalidResponse},
		{name: "not json", status: http.StatusOK, body: `ok`, want: ErrProviderVerificationInvalidResponse},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"message":"Unauthorized"}`, want: ErrProviderCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: `{"message":"Forbidden"}`, want: ErrProviderCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, body: `{"message":"Rate Limit Exceeded","details":"x"}`,
			want: ErrProviderVerificationRateLimited},
		{name: "unavailable", status: http.StatusServiceUnavailable, body: `{"message":"Service Unavailable"}`,
			want: ErrProviderVerificationUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, token, ok := r.BasicAuth()
				if r.URL.Path != "/core/v1/hello" || r.Host != nameComVerifyHost || !ok || user != "fixture-user" ||
					token != "fixture-token" {
					t.Errorf("request %s %s host=%s auth=%v", r.Method, r.URL.Path, r.Host, ok)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verifier := newNameComProviderVerifier(server.URL+"/core/v1/hello", server.Client(), time.Second)
			err := verifier.Verify(context.Background(), "fixture-user", "fixture-token")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNameComCredentialSchema(t *testing.T) {
	if !validProviderCredentialSchema("namecom", map[string]string{"username": "u-test", "api_token": "t0k"}) {
		t.Fatal("valid name.com credentials refused")
	}
	for _, bad := range []map[string]string{
		{"username": "u"},
		{"username": "a:b", "api_token": "t"},
		{"username": "u", "api_token": "has space"},
		{"username": "u", "api_token": "t", "extra": "x"},
	} {
		if validProviderCredentialSchema("namecom", bad) {
			t.Fatalf("invalid credentials accepted: %v", bad)
		}
	}
	if !supportedProvider("namecom") || PlatformMinTTLFor("namecom") != 300 {
		t.Fatal("namecom not supported or TTL floor wrong")
	}
	if err := NewProviderVerifierDispatcher().VerifyCredentials(context.Background(), "namecom",
		map[string]string{"username": "u"}); !errors.Is(err, ErrProviderCredentialsInvalid) {
		t.Fatalf("dispatcher with incomplete credentials = %v", err)
	}
}
