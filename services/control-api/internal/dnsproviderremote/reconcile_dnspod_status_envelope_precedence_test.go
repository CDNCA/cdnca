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

func TestDNSPodReconcileKnownEnvelopePrecedesGenericHTTPStatus(t *testing.T) {
	const (
		providerID      = "dnspod-envelope-provider-id"
		providerSecret  = "dnspod-envelope-provider-secret"
		providerMessage = "dnspod-envelope-sensitive-message"
	)
	tests := []struct {
		name       string
		status     int
		code       string
		body       string
		retryAfter string
		want       ErrorCode
		temporary  bool
		wantRetry  time.Duration
	}{
		{
			name: "forbidden throttling", status: http.StatusForbidden, code: "-2",
			retryAfter: "37", want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
		},
		{
			name: "rate status rejected credential", status: http.StatusTooManyRequests,
			code: "-1", want: CodeCredentialsRejected,
		},
		{
			name: "unknown envelope uses rate fallback", status: http.StatusTooManyRequests,
			code: "future-provider-code", retryAfter: "37",
			want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
		},
		{
			name: "malformed envelope uses rate fallback", status: http.StatusTooManyRequests,
			body: "{", retryAfter: "37",
			want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			config := ProviderConfig{
				ProviderType: providerDNSPodCN,
				ZoneName:     testZone,
				Credentials: map[string]string{
					"dp_id": providerID, "dp_key": providerSecret,
				},
			}
			adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if err := r.ParseForm(); err != nil {
					t.Fatalf("ParseForm() error = %v", err)
				}
				if r.Method != http.MethodPost || r.URL.Path != "/Record.List" ||
					r.Form.Get("error_on_empty") != "no" || r.Form.Get("format") != "json" ||
					r.Form.Get("lang") != "en" || r.Form.Get("login_token") != providerID+","+providerSecret ||
					r.Form.Get("domain") != testZone || r.Form.Get("sub_domain") != testRelative ||
					r.Form.Get("record_type") != "A" || r.Form.Get("record_line") != "默认" ||
					r.Form.Get("offset") != "0" || r.Form.Get("length") != "100" {
					t.Fatalf("unexpected request: %s %s form=%v", r.Method, r.URL.RequestURI(), r.Form)
				}
				w.Header().Set("Retry-After", test.retryAfter)
				w.WriteHeader(test.status)
				if test.body != "" {
					_, _ = w.Write([]byte(test.body))
					return
				}
				writeTestJSON(t, w, map[string]any{
					"status": map[string]any{"code": test.code, "message": providerMessage},
				})
			}), time.Second)
			provider := &dnsPodProvider{adapter: adapter}
			_, err := provider.reconcileLookup(t.Context(), completeTestConfig(config), dnscheck.ProviderOperation{
				Action: dnscheck.ProviderCreate, Name: testOwner,
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
			})
			var remote *Error
			if !errors.As(err, &remote) || remote.Code != test.want || remote.Temporary != test.temporary ||
				remote.RetryAfter != test.wantRetry {
				t.Fatalf("reconcileLookup() error = %+v, want %s temporary=%t retry-after=%s",
					err, test.want, test.temporary, test.wantRetry)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
			formatted := fmt.Sprintf("%+v", err)
			for _, sensitive := range []string{providerID, providerSecret, providerMessage, "login_token"} {
				if strings.Contains(err.Error(), sensitive) || strings.Contains(formatted, sensitive) {
					t.Fatalf("error leaked %q: %v", sensitive, err)
				}
			}
		})
	}
}
