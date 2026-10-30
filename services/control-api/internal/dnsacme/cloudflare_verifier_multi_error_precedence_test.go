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

func TestCloudflareProviderVerifierMultiErrorPrecedence(t *testing.T) {
	const (
		token          = "cloudflare-precedence-token"
		upstreamSecret = "cloudflare-precedence-upstream"
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
			name: "credential after rate overrides http rate", status: http.StatusTooManyRequests,
			body:       `{"success":false,"errors":[{"code":1015},{"code":9109,"message":"` + upstreamSecret + `"}]}`,
			retryAfter: "37", want: ErrProviderCredentialsRejected,
		},
		{
			name: "credential before rate overrides unavailable", status: http.StatusBadGateway,
			body:       `{"success":false,"errors":[{"code":10000,"message":"` + upstreamSecret + `"},{"code":1015}]}`,
			retryAfter: "41", want: ErrProviderCredentialsRejected,
		},
		{
			name: "rate only preserves retry after", status: http.StatusBadGateway,
			body:       `{"success":false,"errors":[{"code":1015,"message":"` + upstreamSecret + `"}]}`,
			retryAfter: "43", want: ErrProviderVerificationRateLimited, wantRetry: "43",
		},
		{
			name: "unknown envelope uses http rate", status: http.StatusTooManyRequests,
			body:       `{"success":false,"errors":[{"code":7777,"message":"` + upstreamSecret + `"}]}`,
			retryAfter: "47", want: ErrProviderVerificationRateLimited, wantRetry: "47",
		},
		{
			name: "malformed envelope uses unavailable status", status: http.StatusBadGateway,
			body: `{"success":`, want: ErrProviderVerificationUnavailable,
		},
		{
			name: "active remains successful", status: http.StatusOK,
			body: `{"success":true,"result":{"id":"token-id","status":"active"}}`,
		},
		{
			name: "inactive remains inactive", status: http.StatusOK,
			body: `{"success":true,"result":{"id":"token-id","status":"expired"}}`,
			want: ErrProviderTokenInactive,
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

			err := newCloudflareProviderVerifier(server.URL, server.Client(), time.Second).
				Verify(context.Background(), "cloudflare", token)
			if !errors.Is(err, test.want) || ProviderVerificationRetryAfter(err) != test.wantRetry {
				t.Fatalf("Verify() error=%v retry=%q, want %v retry=%q",
					err, ProviderVerificationRetryAfter(err), test.want, test.wantRetry)
			}
			if err != nil && (strings.Contains(err.Error(), token) || strings.Contains(err.Error(), upstreamSecret)) {
				t.Fatalf("error leaked sensitive value: %v", err)
			}
		})
	}
}
