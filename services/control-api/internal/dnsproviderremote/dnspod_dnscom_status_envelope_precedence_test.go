package dnsproviderremote

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDNSPodKnownEnvelopePrecedesGenericHTTPStatus(t *testing.T) {
	const (
		providerSecret  = "dnspod-envelope-secret"
		providerMessage = "dnspod-envelope-sensitive-message"
	)
	cases := []struct {
		name       string
		status     int
		code       string
		retryAfter string
		want       ErrorCode
		temporary  bool
		wantRetry  time.Duration
	}{
		{
			name: "forbidden rate limit", status: http.StatusForbidden, code: "-2",
			retryAfter: "37", want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
		},
		{name: "rate status login rejected", status: http.StatusTooManyRequests, code: "-1", want: CodeCredentialsRejected},
		{name: "rate status token rejected", status: http.StatusTooManyRequests, code: "-7", want: CodeCredentialsRejected},
		{name: "rate status account rejected", status: http.StatusTooManyRequests, code: "-8", want: CodeCredentialsRejected},
		{name: "rate status permission rejected", status: http.StatusTooManyRequests, code: "85", want: CodeCredentialsRejected},
		{name: "forbidden unavailable", status: http.StatusForbidden, code: "-99", want: CodeUnavailable, temporary: true},
		{name: "rate status record absent", status: http.StatusTooManyRequests, code: "10", want: CodeRecordNotFound},
	}
	operations := []struct {
		name string
		run  func(context.Context, *dnsPodProvider, ProviderConfig, recordHandle) error
	}{
		{
			name: "create",
			run: func(ctx context.Context, provider *dnsPodProvider, config ProviderConfig, _ recordHandle) error {
				_, err := provider.present(ctx, config, testOwner, testRelative, testValue)
				return err
			},
		},
		{
			name: "get",
			run: func(ctx context.Context, provider *dnsPodProvider, config ProviderConfig, handle recordHandle) error {
				_, _, err := provider.get(ctx, config, handle, testValue)
				return err
			},
		},
		{
			name: "delete",
			run: func(ctx context.Context, provider *dnsPodProvider, config ProviderConfig, handle recordHandle) error {
				return provider.delete(ctx, config, handle)
			},
		},
		{
			name: "list",
			run: func(ctx context.Context, provider *dnsPodProvider, config ProviderConfig, _ recordHandle) error {
				_, err := provider.request(ctx, config, "/Record.List", url.Values{"domain": {testZone}})
				return err
			},
		},
	}

	for _, test := range cases {
		for _, operation := range operations {
			t.Run(test.name+"/"+operation.name, func(t *testing.T) {
				config := ProviderConfig{
					ProviderType: providerDNSPodCN,
					ZoneName:     testZone,
					Credentials:  map[string]string{"dp_id": "12345", "dp_key": providerSecret},
				}
				adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Retry-After", test.retryAfter)
					writer.WriteHeader(test.status)
					writeTestJSON(t, writer, map[string]any{
						"status": map[string]any{"code": test.code, "message": providerMessage},
					})
				}), time.Second)
				handle := recordHandle{
					Provider: providerDNSPodCN, Zone: testZone, ZoneID: testZone,
					RecordID: "record-dnspod", Owner: testOwner,
				}
				provider := &dnsPodProvider{adapter: adapter}
				if test.code == "10" && operation.name == "get" {
					_, exists, err := provider.get(t.Context(), config, handle, testValue)
					if err != nil || exists {
						t.Fatalf("get error = %+v, exists = %t, want nil/false", err, exists)
					}
					return
				}

				err := operation.run(t.Context(), provider, config, handle)
				var remote *Error
				if !errors.As(err, &remote) || remote.Code != test.want || remote.Temporary != test.temporary ||
					remote.RetryAfter != test.wantRetry {
					t.Fatalf("%s error = %+v, want %s temporary=%t retry=%s",
						operation.name, err, test.want, test.temporary, test.wantRetry)
				}
				for _, sensitive := range []string{providerSecret, providerMessage, "login_token"} {
					if strings.Contains(err.Error(), sensitive) {
						t.Fatalf("%s error leaked %q: %v", operation.name, sensitive, err)
					}
				}
			})
		}
	}
}

func TestDNSComUnknownEnvelopeFallsBackToGenericHTTPStatus(t *testing.T) {
	const (
		providerSecret  = "dnscom-envelope-secret"
		providerMessage = "dnscom-envelope-sensitive-message"
	)
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       ErrorCode
		wantRetry  time.Duration
	}{
		{
			name: "unknown envelope uses forbidden", status: http.StatusForbidden,
			body: `{"code":9876,"message":"` + providerMessage + `"}`, want: CodeCredentialsRejected,
		},
		{
			name: "unknown envelope uses rate status", status: http.StatusTooManyRequests,
			body:       `{"code":9876,"message":"` + providerMessage + `"}`,
			retryAfter: "37", want: CodeRateLimited, wantRetry: 37 * time.Second,
		},
		{name: "malformed envelope uses forbidden", status: http.StatusForbidden, body: `{"code":`, want: CodeCredentialsRejected},
		{
			name: "malformed envelope uses rate status", status: http.StatusTooManyRequests, body: `{"code":`,
			retryAfter: "37", want: CodeRateLimited, wantRetry: 37 * time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := ProviderConfig{
				ProviderType: providerDNSCom,
				ZoneName:     testZone,
				Credentials:  map[string]string{"api_key": "dnscom-key", "api_secret": providerSecret},
			}
			adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Retry-After", test.retryAfter)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}), time.Second)

			_, err := (&dnsComProvider{adapter: adapter}).request(t.Context(), config,
				"/api/record/getOne/", map[string]string{"domain": "zone-id", "record_id": "record-id"})
			var remote *Error
			if !errors.As(err, &remote) || remote.Code != test.want || remote.RetryAfter != test.wantRetry {
				t.Fatalf("error = %+v, want %s retry=%s", err, test.want, test.wantRetry)
			}
			for _, sensitive := range []string{providerSecret, providerMessage, "api_secret", "sign"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error leaked %q: %v", sensitive, err)
				}
			}
		})
	}
}
