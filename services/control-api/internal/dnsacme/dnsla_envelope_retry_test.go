package dnsacme

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDNSLAProviderVerifierClassifiesRetryableEnvelopeCodes(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "rate limited", code: http.StatusTooManyRequests, retryAfter: "37", want: ErrProviderVerificationRateLimited, wantRetry: "37"},
		{name: "rate limited invalid hint", code: http.StatusTooManyRequests, retryAfter: dnslaTestUpstream, want: ErrProviderVerificationRateLimited},
		{name: "not implemented", code: http.StatusNotImplemented, want: ErrProviderVerificationUnavailable},
		{name: "provider 599", code: 599, want: ErrProviderVerificationUnavailable},
		{name: "unknown 2xx", code: http.StatusCreated, want: ErrProviderVerificationInvalidResponse},
		{name: "unknown 299", code: 299, want: ErrProviderVerificationInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Retry-After", test.retryAfter)
				_, _ = writer.Write([]byte(`{"code":` + strconv.Itoa(test.code) + `,"msg":"` + dnslaTestUpstream + `","data":null}`))
			}))
			t.Cleanup(server.Close)
			err := newDNSLATestVerifier(server).Verify(t.Context(), dnslaTestAPIID, dnslaTestAPISecret)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retryAfter, test.wantRetry)
			}
			for _, sensitive := range []string{dnslaTestAPIID, dnslaTestAPISecret, dnslaTestUpstream} {
				if strings.Contains(err.Error(), sensitive) || strings.Contains(ProviderVerificationRetryAfter(err), sensitive) {
					t.Fatalf("error leaked sensitive value %q", sensitive)
				}
			}
		})
	}
}
