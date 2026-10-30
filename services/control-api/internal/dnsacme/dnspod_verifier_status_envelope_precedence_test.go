package dnsacme

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSPodProviderVerifierKnownEnvelopePrecedesHTTPStatus(t *testing.T) {
	const upstreamSecret = "dnspod-precedence-sensitive-upstream"
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "login rejection overrides rate", status: http.StatusTooManyRequests,
			body: `{"status":{"code":"-1","message":"` + upstreamSecret + `"}}`, want: ErrProviderCredentialsRejected},
		{name: "permission rejection overrides unavailable", status: http.StatusBadGateway,
			body: `{"status":{"code":"-7","message":"` + upstreamSecret + `"}}`, want: ErrProviderCredentialsRejected},
		{name: "temporary block overrides rate", status: http.StatusTooManyRequests,
			body: `{"status":{"code":"-8","message":"` + upstreamSecret + `"}}`, want: ErrProviderCredentialsRejected},
		{name: "remote login denial overrides unavailable", status: http.StatusServiceUnavailable,
			body: `{"status":{"code":"85","message":"` + upstreamSecret + `"}}`, want: ErrProviderCredentialsRejected},
		{name: "provider rate limit overrides forbidden", status: http.StatusForbidden,
			body: `{"status":{"code":"-2","message":"` + upstreamSecret + `"}}`, retryAfter: "37",
			want: ErrProviderVerificationRateLimited, wantRetry: "37"},
		{name: "provider unavailable overrides forbidden", status: http.StatusForbidden,
			body: `{"status":{"code":"-99","message":"` + upstreamSecret + `"}}`, want: ErrProviderVerificationUnavailable},
		{name: "unknown envelope uses rate status", status: http.StatusTooManyRequests,
			body: `{"status":{"code":"future","message":"` + upstreamSecret + `"}}`, retryAfter: "37",
			want: ErrProviderVerificationRateLimited, wantRetry: "37"},
		{name: "malformed envelope uses forbidden status", status: http.StatusForbidden,
			body: `{"status":`, want: ErrProviderCredentialsRejected},
		{name: "success envelope still obeys forbidden status", status: http.StatusForbidden,
			body: `{"status":{"code":"1"},"info":{"user":{}}}`, want: ErrProviderCredentialsRejected},
		{name: "valid success remains valid", status: http.StatusOK,
			body: `{"status":{"code":"1"},"info":{"user":{}}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Retry-After", test.retryAfter)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)

			err := newDNSPodTestVerifier(server).Verify(t.Context(), dnspodTestID, dnspodTestKey)
			if !errors.Is(err, test.want) || ProviderVerificationRetryAfter(err) != test.wantRetry {
				t.Fatalf("Verify() error=%v retry=%q, want %v retry=%q",
					err, ProviderVerificationRetryAfter(err), test.want, test.wantRetry)
			}
			if err != nil {
				for _, sensitive := range []string{dnspodTestID, dnspodTestKey, upstreamSecret, "login_token"} {
					if strings.Contains(err.Error(), sensitive) {
						t.Fatalf("error leaked %q: %v", sensitive, err)
					}
				}
			}
		})
	}
}
