package dnsproviderremote

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

func TestCloudflareReconcileKnownEnvelopePrecedesGenericHTTPStatus(t *testing.T) {
	const (
		token           = "cloudflare-reconcile-secret-token"
		providerMessage = "cloudflare-reconcile-sensitive-message"
		zoneID          = "zone-cf-reconcile"
	)
	paths := []struct {
		name      string
		operation dnscheck.ProviderOperation
	}{
		{name: "direct record", operation: dnscheck.ProviderOperation{
			Action: dnscheck.ProviderUpdate, RecordID: "record-cf-target",
			Name: testOwner, Type: dnscheck.RecordTXT, Value: testValue, TTL: 300,
		}},
		{name: "create pagination", operation: dnscheck.ProviderOperation{
			Action: dnscheck.ProviderCreate, Name: testOwner, Type: dnscheck.RecordTXT, Value: testValue, TTL: 300,
		}},
	}
	cases := []struct {
		name       string
		status     int
		body       string
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
		{
			name: "unknown code uses forbidden fallback", status: http.StatusForbidden, code: 7777,
			want: CodeCredentialsRejected,
		},
		{
			name: "malformed envelope uses rate fallback", status: http.StatusTooManyRequests, body: "{",
			retryAfter: "37", want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
		},
	}

	for _, path := range paths {
		for _, test := range cases {
			t.Run(path.name+"/"+test.name, func(t *testing.T) {
				config := completeTestConfig(reconcileHTTPProviderConfig(providerCloudflare))
				config.Credentials["api_token"] = token
				lookupCalls, mutations := 0, 0
				providerAdapter, _ := newProviderTestAdapter(t, config,
					http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
						if request.Method != http.MethodGet {
							mutations++
							writer.WriteHeader(http.StatusMethodNotAllowed)
							return
						}
						if request.Header.Get("Authorization") != "Bearer "+token {
							t.Error("request did not use the expected credential")
						}
						if request.URL.Path == "/zones" {
							writeTestJSON(t, writer, map[string]any{"success": true, "result": []any{
								map[string]any{"id": zoneID, "name": testZone},
							}})
							return
						}
						lookupCalls++
						writer.Header().Set("Retry-After", test.retryAfter)
						writer.WriteHeader(test.status)
						if test.body != "" {
							_, _ = writer.Write([]byte(test.body))
							return
						}
						writeTestJSON(t, writer, map[string]any{
							"success": false, "result": nil,
							"errors": []map[string]any{{"code": test.code, "message": providerMessage}},
						})
					}), time.Second)
				provider := &cloudflareProvider{adapter: providerAdapter}
				_, err := provider.reconcileLookup(t.Context(), config, path.operation)
				var remote *Error
				if !errors.As(err, &remote) || remote.Code != test.want || remote.Temporary != test.temporary ||
					remote.RetryAfter != test.wantRetry {
					t.Fatalf("reconcileLookup() error=%+v want=%s temporary=%t retry=%s",
						err, test.want, test.temporary, test.wantRetry)
				}
				if lookupCalls != 1 || mutations != 0 {
					t.Fatalf("lookup calls=%d mutations=%d", lookupCalls, mutations)
				}
				formatted := fmt.Sprintf("%+v", err)
				for _, sensitive := range []string{token, providerMessage, "Authorization", "Bearer"} {
					if strings.Contains(err.Error(), sensitive) || strings.Contains(formatted, sensitive) {
						t.Fatalf("error leaked %q: %v", sensitive, err)
					}
				}
			})
		}
	}
}
