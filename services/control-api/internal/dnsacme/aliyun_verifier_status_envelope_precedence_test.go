package dnsacme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAliyunProviderVerifierKnownEnvelopePrecedesHTTPStatus(t *testing.T) {
	const (
		accessKeyID     = "precedence-access-key"
		accessKeySecret = "precedence-access-secret"
		upstreamSecret  = "precedence-sensitive-upstream"
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
			name: "known throttling overrides forbidden", status: http.StatusForbidden,
			body:       `{"RequestId":"request-id","Code":"Throttling.User","Message":"` + upstreamSecret + `"}`,
			retryAfter: "37", want: ErrProviderVerificationRateLimited, wantRetry: "37",
		},
		{
			name: "known credential rejection overrides rate status", status: http.StatusTooManyRequests,
			body:       `{"RequestId":"request-id","Code":"SignatureDoesNotMatch","Message":"` + upstreamSecret + `"}`,
			retryAfter: "37", want: ErrProviderCredentialsRejected,
		},
		{
			name: "known credential rejection overrides unavailable status", status: http.StatusBadGateway,
			body: `{"RequestId":"request-id","Code":"InvalidAccessKeyId.NotFound","Message":"` + upstreamSecret + `"}`,
			want: ErrProviderCredentialsRejected,
		},
		{
			name: "unknown envelope uses rate status", status: http.StatusTooManyRequests,
			body:       `{"RequestId":"request-id","Code":"InvalidParameter","Message":"` + upstreamSecret + `"}`,
			retryAfter: "37", want: ErrProviderVerificationRateLimited, wantRetry: "37",
		},
		{
			name: "malformed envelope uses forbidden status", status: http.StatusForbidden,
			body: `{"Message":`, want: ErrProviderCredentialsRejected,
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

			err := newAliyunTestVerifier(server).Verify(context.Background(), accessKeyID, accessKeySecret)
			if !errors.Is(err, test.want) || ProviderVerificationRetryAfter(err) != test.wantRetry {
				t.Fatalf("Verify() error=%v retry=%q, want %v retry=%q",
					err, ProviderVerificationRetryAfter(err), test.want, test.wantRetry)
			}
			for _, sensitive := range []string{accessKeyID, accessKeySecret, upstreamSecret} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error leaked %q: %v", sensitive, err)
				}
			}
		})
	}
}
