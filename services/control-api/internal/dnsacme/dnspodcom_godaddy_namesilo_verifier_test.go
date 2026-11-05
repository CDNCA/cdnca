package dnsacme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test-only credentials; requests go to the httptest server only. Bodies
// follow the providers' documented samples (read 2026-11-05).

func TestDNSPodComProviderVerifier(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want error
	}{
		{name: "accepted", body: `{"status":{"code":"1","message":"Action completed successful"},"info":{"user":{"id":"730060","email":"x@example.test"}}}`},
		{name: "login failed", body: `{"status":{"code":"-1","message":"Login fail"}}`, want: ErrProviderCredentialsRejected},
		{name: "too frequent", body: `{"status":{"code":"-2","message":"API used too frequently"}}`, want: ErrProviderVerificationRateLimited},
		{name: "no user", body: `{"status":{"code":"1"},"info":{}}`, want: ErrProviderVerificationInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				if r.Method != http.MethodPost || r.URL.Path != "/User.Detail" || r.Host != dnspodComVerifyHost ||
					r.PostForm.Get("login_token") != "730060,fixture-token" || r.PostForm.Get("format") != "json" {
					t.Errorf("request %s %s host=%s form=%v", r.Method, r.URL.Path, r.Host, r.PostForm)
				}
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verifier := NewDNSPodComProviderVerifier()
			verifier.testEndpoint, verifier.client = server.URL+"/User.Detail", server.Client()
			err := verifier.Verify(context.Background(), "730060", "fixture-token")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
	// The dnsapi.cn verifier keeps its own host.
	if verifier := NewDNSPodProviderVerifier(); verifier.endpoint != "" || verifier.host != "" {
		t.Fatalf("dnspod_cn verifier = %+v", verifier)
	}
}

func TestGoDaddyProviderVerifier(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "accepted", status: http.StatusOK, body: `[{"domain":"example.test","status":"ACTIVE"}]`},
		{name: "no domains", status: http.StatusOK, body: `[]`},
		{name: "bad key", status: http.StatusUnauthorized, body: `{"code":"UNABLE_TO_AUTHENTICATE"}`, want: ErrProviderCredentialsRejected},
		{name: "ineligible account", status: http.StatusForbidden, body: `{"code":"ACCESS_DENIED"}`, want: ErrProviderCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, body: `{"code":"TOO_MANY_REQUESTS","retryAfterSec":30}`,
			want: ErrProviderVerificationRateLimited},
		{name: "gateway timeout", status: http.StatusGatewayTimeout, want: ErrProviderVerificationUnavailable},
		{name: "object", status: http.StatusOK, body: `{"domain":"x"}`, want: ErrProviderVerificationInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/domains" || r.Host != goDaddyVerifyHost ||
					r.Header.Get("Authorization") != "sso-key fixture-key:fixture-secret" {
					t.Errorf("request %s %s host=%s auth=%q", r.Method, r.URL.Path, r.Host, r.Header.Get("Authorization"))
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verifier := newGoDaddyProviderVerifier(server.URL+"/v1/domains?limit=1", server.Client(), time.Second)
			err := verifier.Verify(context.Background(), "fixture-key", "fixture-secret")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNamesiloProviderVerifier(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want error
	}{
		{name: "accepted", body: `{"request":{"operation":"listDomains","ip":"192.0.2.1"},"reply":{"code":300,"detail":"success"}}`},
		{name: "string code", body: `{"reply":{"code":"300","detail":"success"}}`},
		{name: "invalid key", body: `{"reply":{"code":"110","detail":"Invalid API Key"}}`, want: ErrProviderCredentialsRejected},
		{name: "ip refused", body: `{"reply":{"code":113,"detail":"This API account cannot be accessed from your IP"}}`,
			want: ErrProviderCredentialsRejected},
		{name: "still processing", body: `{"reply":{"code":400}}`, want: ErrProviderVerificationRateLimited},
		{name: "no reply", body: `{}`, want: ErrProviderVerificationInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				if r.Method != http.MethodGet || r.URL.Path != "/api/listDomains" || r.Host != namesiloVerifyHost ||
					query.Get("key") != "fixture-key" || query.Get("type") != "json" || query.Get("version") != "1" {
					t.Errorf("request %s %s host=%s query=%v", r.Method, r.URL.Path, r.Host, query)
				}
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verifier := newNamesiloProviderVerifier(server.URL+"/api/listDomains", server.Client(), time.Second)
			err := verifier.Verify(context.Background(), "fixture-key")
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
	// A transport failure never returns the URL (it holds the key).
	verifier := newNamesiloProviderVerifier("https://127.0.0.1:1/api/listDomains", nil, time.Second)
	if err := verifier.Verify(context.Background(), "secret-key-value"); err == nil || strings.Contains(err.Error(), "secret-key-value") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestDNSPodComGoDaddyNamesiloCredentialSchemas(t *testing.T) {
	for providerType, test := range map[string]struct {
		valid map[string]string
		bad   []map[string]string
		ttl   int
	}{
		"dnspod_com": {valid: map[string]string{"dp_id": "730060", "dp_key": "tok"}, ttl: 600,
			bad: []map[string]string{{"dp_id": "x", "dp_key": "t"}, {"dp_id": "1"}, {"dp_id": "1", "dp_key": "a,b"}}},
		"godaddy": {valid: map[string]string{"api_key": "k", "api_secret": "s"}, ttl: 600,
			bad: []map[string]string{{"api_key": "a:b", "api_secret": "s"}, {"api_key": "k"}, {"api_key": "k", "api_secret": "s", "x": "y"}}},
		"namesilo": {valid: map[string]string{"key": "abc123"}, ttl: 3600,
			bad: []map[string]string{{"key": "a b"}, {}, {"key": "k", "api_secret": "s"}, {"api_key": "abc123"}}},
	} {
		if !supportedProvider(providerType) || PlatformMinTTLFor(providerType) != test.ttl {
			t.Fatalf("%s supported=%v ttl=%d", providerType, supportedProvider(providerType), PlatformMinTTLFor(providerType))
		}
		if !validProviderCredentialSchema(providerType, test.valid) || !matchesSupportedProviderCredentialSchema(test.valid) {
			t.Fatalf("%s valid credentials refused", providerType)
		}
		for _, bad := range test.bad {
			if validProviderCredentialSchema(providerType, bad) {
				t.Errorf("%s accepted %v", providerType, bad)
			}
			if err := NewProviderVerifierDispatcher().VerifyCredentials(context.Background(), providerType, bad); !errors.Is(err, ErrProviderCredentialsInvalid) {
				t.Errorf("%s dispatcher(%v) = %v", providerType, bad, err)
			}
		}
	}
	// A DNS.COM / GoDaddy map missing its secret matches no schema (the
	// update path rejects it before the store; Namesilo's field is "key").
	if matchesSupportedProviderCredentialSchema(map[string]string{"api_key": "c7722149110b7492a2e5cf1d8f3f966b"}) {
		t.Fatal("api_key alone matched a provider schema")
	}
	// Identifiers shown back: never the secret (Namesilo's only field is its key).
	if got := identifierFields["namesilo"]; len(got) != 0 {
		t.Fatalf("namesilo identifiers = %v", got)
	}
	if got := identifierFields["godaddy"]; len(got) != 1 || got[0] != "api_key" {
		t.Fatalf("godaddy identifiers = %v", got)
	}
}
