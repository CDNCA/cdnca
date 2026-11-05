package dnsacme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

// Test-only credentials; requests go to the httptest server only. The fake
// recomputes the JDCLOUD2 signature and refuses a mismatch with 401.
func TestJDCloudProviderVerifier(t *testing.T) {
	for _, test := range []struct {
		name   string
		secret string
		status int
		body   string
		want   error
	}{
		{name: "accepted", secret: "fixture-sk", status: http.StatusOK,
			body: `{"requestId":"r","result":{"dataList":[],"totalCount":0,"totalPage":0,"currentCount":0}}`},
		{name: "bad signature", secret: "wrong-sk", want: ErrProviderCredentialsRejected},
		{name: "forbidden", secret: "fixture-sk", status: http.StatusForbidden,
			body: `{"requestId":"r","error":{"code":403,"status":"HTTP_FORBIDDEN","message":"x"}}`, want: ErrProviderCredentialsRejected},
		{name: "error on 200", secret: "fixture-sk", status: http.StatusOK,
			body: `{"requestId":"r","error":{"code":401,"status":"UNAUTHENTICATED","message":"x"}}`, want: ErrProviderCredentialsRejected},
		{name: "rate limited", secret: "fixture-sk", status: http.StatusTooManyRequests,
			body: `{"requestId":"r","error":{"code":429,"status":"RATE_LIMIT","message":"x"}}`, want: ErrProviderVerificationRateLimited},
		{name: "unavailable", secret: "fixture-sk", status: http.StatusServiceUnavailable, body: `{}`, want: ErrProviderVerificationUnavailable},
		{name: "no result", secret: "fixture-sk", status: http.StatusOK, body: `{"requestId":"r"}`, want: ErrProviderVerificationInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				at, _ := time.Parse("20060102T150405Z", r.Header.Get("x-jdcloud-date"))
				want := dnsproviderremote.JDCloudSignature("fixture-ak", "fixture-sk", "cn-north-1", "domainservice", r.Method,
					r.URL.Path, r.URL.Query(), map[string]string{"content-type": r.Header.Get("Content-Type"), "host": r.Host,
						"x-jdcloud-date": r.Header.Get("x-jdcloud-date"), "x-jdcloud-nonce": r.Header.Get("x-jdcloud-nonce")}, nil, at)
				if r.Method != http.MethodGet || r.URL.Path != jdCloudVerifyPath || r.Host != jdCloudVerifyHost {
					t.Errorf("request %s %s host=%s", r.Method, r.URL.Path, r.Host)
				}
				if r.Header.Get("Authorization") != want || !strings.HasPrefix(want, "JDCLOUD2-HMAC-SHA256 Credential=fixture-ak/") {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"requestId":"r","error":{"code":401,"status":"UNAUTHENTICATED","message":"x"}}`))
					return
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			verifier := newJDCloudProviderVerifier(server.URL, server.Client(), time.Second)
			err := verifier.Verify(context.Background(), "fixture-ak", test.secret)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("Verify = %v, want %v", err, test.want)
			}
		})
	}
}

func TestJDCloudCredentialSchema(t *testing.T) {
	if !validProviderCredentialSchema("jdcloud", map[string]string{"access_key_id": "a", "access_key_secret": "b"}) {
		t.Fatal("valid JD Cloud credentials refused")
	}
	for _, bad := range []map[string]string{
		{"access_key_id": "a"},
		{"access_key_id": "a", "access_key_secret": "b c"},
		{"access_key_id": "a", "access_key_secret": "b", "region": "cn-north-1"},
	} {
		if validProviderCredentialSchema("jdcloud", bad) {
			t.Fatalf("invalid credentials accepted: %v", bad)
		}
	}
	if !supportedProvider("jdcloud") || PlatformMinTTLFor("jdcloud") != 120 {
		t.Fatal("jdcloud not supported or TTL floor wrong")
	}
	if err := NewProviderVerifierDispatcher().VerifyCredentials(context.Background(), "jdcloud",
		map[string]string{"access_key_id": "a"}); !errors.Is(err, ErrProviderCredentialsInvalid) {
		t.Fatalf("dispatcher with incomplete credentials = %v", err)
	}
}
