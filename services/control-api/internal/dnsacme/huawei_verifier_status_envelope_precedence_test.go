package dnsacme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHuaweiProviderVerifierKnownEnvelopePrecedesHTTPStatus(t *testing.T) {
	const (
		accessKey      = "precedence-access-key"
		secretKey      = "precedence-secret-key"
		upstreamSecret = "precedence-sensitive-upstream"
	)
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{
			name: "known credential rejection overrides rate status", status: http.StatusTooManyRequests,
			body:       `{"error_code":"APIGW.0301","error_msg":"` + upstreamSecret + `"}`,
			retryAfter: "37", want: ErrProviderCredentialsRejected,
		},
		{
			name: "known credential rejection overrides unavailable status", status: http.StatusBadGateway,
			body: `{"error_code":"APIGW.0301","error_msg":"` + upstreamSecret + `"}`,
			want: ErrProviderCredentialsRejected,
		},
		{
			name: "unknown envelope uses rate status", status: http.StatusTooManyRequests,
			body:       `{"error_code":"DNS.0001","error_msg":"` + upstreamSecret + `"}`,
			retryAfter: "37", want: ErrProviderVerificationRateLimited, wantRetry: "37",
		},
		{
			name: "unknown envelope uses unavailable status", status: http.StatusBadGateway,
			body: `{"error_code":"DNS.0001","error_msg":"` + upstreamSecret + `"}`,
			want: ErrProviderVerificationUnavailable,
		},
		{
			name: "malformed envelope uses rate status", status: http.StatusTooManyRequests,
			body: `{"error_code":`, retryAfter: "37",
			want: ErrProviderVerificationRateLimited, wantRetry: "37",
		},
		{
			name: "malformed envelope uses unavailable status", status: http.StatusBadGateway,
			body: `{"error_code":`, want: ErrProviderVerificationUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Retry-After", test.retryAfter)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)

			err := newHuaweiTestVerifier(server).Verify(
				context.Background(), "cn-north-4", "project-id", accessKey, secretKey,
			)
			if !errors.Is(err, test.want) || ProviderVerificationRetryAfter(err) != test.wantRetry {
				t.Fatalf("Verify() error=%v retry=%q, want %v retry=%q",
					err, ProviderVerificationRetryAfter(err), test.want, test.wantRetry)
			}
			for _, sensitive := range []string{accessKey, secretKey, upstreamSecret, "Authorization"} {
				if strings.Contains(err.Error(), sensitive) || strings.Contains(ProviderVerificationRetryAfter(err), sensitive) {
					t.Fatalf("error leaked %q: %v", sensitive, err)
				}
			}
		})
	}
}
