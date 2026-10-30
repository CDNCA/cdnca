package dnsproviderremote

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCloudflareCredentialErrorPrecedesRateLimitAcrossEnvelopeOrder(t *testing.T) {
	const (
		token           = "cloudflare-multi-error-secret-token"
		providerMessage = "cloudflare-multi-error-sensitive-message"
	)
	tests := []struct {
		name      string
		codes     []int
		want      ErrorCode
		temporary bool
		wantRetry time.Duration
	}{
		{name: "rate then credential", codes: []int{1015, 9109}, want: CodeCredentialsRejected},
		{name: "credential then rate", codes: []int{10000, 1015}, want: CodeCredentialsRejected},
		{name: "rate only", codes: []int{1015}, want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second},
	}
	operations := []struct {
		name string
		run  func(context.Context, *cloudflareProvider, ProviderConfig, recordHandle) error
	}{
		{
			name: "request",
			run: func(ctx context.Context, provider *cloudflareProvider, _ ProviderConfig, _ recordHandle) error {
				_, err := provider.request(ctx, http.MethodGet, "/zones", token, nil)
				return err
			},
		},
		{
			name: "get",
			run: func(ctx context.Context, provider *cloudflareProvider, config ProviderConfig, handle recordHandle) error {
				_, _, err := provider.get(ctx, config, handle, "")
				return err
			},
		},
		{
			name: "delete",
			run: func(ctx context.Context, provider *cloudflareProvider, config ProviderConfig, handle recordHandle) error {
				return provider.delete(ctx, config, handle)
			},
		},
	}

	for _, test := range tests {
		for _, operation := range operations {
			t.Run(test.name+"/"+operation.name, func(t *testing.T) {
				adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					providerErrors := make([]map[string]any, 0, len(test.codes))
					for _, code := range test.codes {
						providerErrors = append(providerErrors, map[string]any{"code": code, "message": providerMessage})
					}
					writer.Header().Set("Retry-After", "37")
					writer.WriteHeader(http.StatusTooManyRequests)
					writeTestJSON(t, writer, map[string]any{
						"success": false, "result": nil, "errors": providerErrors,
					})
				}), time.Second)
				provider := &cloudflareProvider{adapter: adapter}
				config := ProviderConfig{
					ProviderType: providerCloudflare, ZoneName: testZone,
					Credentials: map[string]string{"api_token": token},
				}
				handle := recordHandle{
					Provider: providerCloudflare, Zone: testZone, ZoneID: "zone-cf",
					RecordID: "record-cf", Owner: testOwner,
				}

				err := operation.run(t.Context(), provider, config, handle)
				var remote *Error
				if !errors.As(err, &remote) || remote.Code != test.want || remote.Temporary != test.temporary ||
					remote.RetryAfter != test.wantRetry {
					t.Fatalf("%s error = %+v, want %s temporary=%t retry=%s",
						operation.name, err, test.want, test.temporary, test.wantRetry)
				}
				for _, secret := range []string{token, providerMessage, "Authorization", "Bearer"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("%s error leaked %q: %v", operation.name, secret, err)
					}
				}
			})
		}
	}
}
