package dnsproviderremote

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCloudflareKnownEnvelopePrecedesGenericHTTPStatus(t *testing.T) {
	const (
		token           = "cloudflare-envelope-secret-token"
		providerMessage = "cloudflare-envelope-sensitive-message"
	)
	tests := []struct {
		name       string
		status     int
		code       int
		retryAfter string
		want       ErrorCode
		temporary  bool
		wantRetry  time.Duration
	}{
		{
			name: "forbidden rate limit", status: http.StatusForbidden, code: 1015,
			retryAfter: "37", want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
		},
		{
			name: "rate status rejected credential", status: http.StatusTooManyRequests, code: 9109,
			want: CodeCredentialsRejected,
		},
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
				config := ProviderConfig{
					ProviderType: providerCloudflare, ZoneName: testZone,
					Credentials: map[string]string{"api_token": token},
				}
				adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Retry-After", test.retryAfter)
					writer.WriteHeader(test.status)
					writeTestJSON(t, writer, map[string]any{
						"success": false,
						"result":  nil,
						"errors": []map[string]any{{
							"code": test.code, "message": providerMessage,
						}},
					})
				}), time.Second)
				provider := &cloudflareProvider{adapter: adapter}
				handle := recordHandle{
					Provider: providerCloudflare, Zone: testZone, ZoneID: "zone-cf",
					RecordID: "record-cf", Owner: testOwner,
				}

				err := operation.run(t.Context(), provider, config, handle)
				var remote *Error
				if !errors.As(err, &remote) || remote.Code != test.want ||
					remote.Temporary != test.temporary || remote.RetryAfter != test.wantRetry {
					t.Fatalf("%s error = %+v, want %s temporary=%t retry=%s",
						operation.name, err, test.want, test.temporary, test.wantRetry)
				}
				for _, sensitive := range []string{token, providerMessage, "Authorization", "Bearer"} {
					if strings.Contains(err.Error(), sensitive) {
						t.Fatalf("%s error leaked %q: %v", operation.name, sensitive, err)
					}
				}
			})
		}
	}
}
