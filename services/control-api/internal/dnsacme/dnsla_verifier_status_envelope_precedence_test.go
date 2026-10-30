package dnsacme

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSLAProviderVerifierKnownEnvelopePrecedesHTTPStatus(t *testing.T) {
	const upstreamSecret = "dnsla-precedence-sensitive-upstream"
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "provider rate limit overrides forbidden", status: http.StatusForbidden,
			body: `{"code":429,"msg":"` + upstreamSecret + `","data":null}`, retryAfter: "37",
			want: ErrProviderVerificationRateLimited, wantRetry: "37"},
		{name: "provider rate limit overrides unavailable", status: http.StatusBadGateway,
			body: `{"code":429,"msg":"` + upstreamSecret + `","data":null}`, retryAfter: "37",
			want: ErrProviderVerificationRateLimited, wantRetry: "37"},
		{name: "provider unavailable overrides forbidden", status: http.StatusForbidden,
			body: `{"code":500,"msg":"` + upstreamSecret + `","data":null}`, want: ErrProviderVerificationUnavailable},
		{name: "provider unavailable overrides rate status", status: http.StatusTooManyRequests,
			body: `{"code":500,"msg":"` + upstreamSecret + `","data":null}`, retryAfter: "37",
			want: ErrProviderVerificationUnavailable},
		{name: "unknown envelope uses rate status", status: http.StatusTooManyRequests,
			body: `{"code":777,"msg":"` + upstreamSecret + `","data":null}`, retryAfter: "37",
			want: ErrProviderVerificationRateLimited, wantRetry: "37"},
		{name: "malformed envelope uses forbidden status", status: http.StatusForbidden,
			body: `{"code":`, want: ErrProviderCredentialsRejected},
		{name: "success envelope cannot override forbidden", status: http.StatusForbidden,
			body: `{"code":200,"data":{"total":0,"results":[]}}`, want: ErrProviderCredentialsRejected},
		{name: "valid success remains valid", status: http.StatusOK,
			body: `{"code":200,"data":{"total":0,"results":[]}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Retry-After", test.retryAfter)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)

			err := newDNSLATestVerifier(server).Verify(t.Context(), dnslaTestAPIID, dnslaTestAPISecret)
			if !errors.Is(err, test.want) || ProviderVerificationRetryAfter(err) != test.wantRetry {
				t.Fatalf("Verify() error=%v retry=%q, want %v retry=%q",
					err, ProviderVerificationRetryAfter(err), test.want, test.wantRetry)
			}
			if err != nil {
				for _, sensitive := range []string{dnslaTestAPIID, dnslaTestAPISecret, upstreamSecret, "Authorization", "Basic"} {
					if strings.Contains(err.Error(), sensitive) || strings.Contains(ProviderVerificationRetryAfter(err), sensitive) {
						t.Fatalf("error leaked %q: %v", sensitive, err)
					}
				}
			}
		})
	}
}
