package dnsproviderremote

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAliyunHuaweiStatusEnvelopePrecedence(t *testing.T) {
	const (
		aliyunAccessKey = "aliyun-envelope-access-key"
		aliyunSecret    = "aliyun-envelope-secret"
		huaweiAccessKey = "huawei-envelope-access-key"
		huaweiSecret    = "huawei-envelope-secret"
		projectID       = "0123456789abcdef0123456789abcdef"
		providerMessage = "sensitive-provider-envelope-message"
	)
	assertError := func(t *testing.T, err error, want ErrorCode, temporary bool, retryAfter time.Duration, sensitive ...string) {
		t.Helper()
		var remote *Error
		if !errors.As(err, &remote) || remote.Code != want || remote.Temporary != temporary ||
			remote.RetryAfter != retryAfter {
			t.Fatalf("error = %+v, want %s temporary=%t retry-after=%s", err, want, temporary, retryAfter)
		}
		formatted := fmt.Sprintf("%+v", err)
		for _, value := range sensitive {
			if strings.Contains(err.Error(), value) || strings.Contains(formatted, value) {
				t.Fatalf("error leaked %q: %v", value, err)
			}
		}
	}

	t.Run("aliyun", func(t *testing.T) {
		actions := []string{
			"AddDomainRecord",
			"DescribeDomainRecordInfo",
			"DeleteDomainRecord",
			"DescribeDomainRecords",
		}
		cases := []struct {
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
				name: "forbidden throttling", status: http.StatusForbidden, code: "Throttling.User",
				retryAfter: "37", want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
			},
			{
				name: "rate status rejected credential", status: http.StatusTooManyRequests,
				code: "Forbidden.RAM", want: CodeCredentialsRejected,
			},
			{
				name: "unknown envelope uses rate fallback", status: http.StatusTooManyRequests,
				code: "Future.Provider.Code", retryAfter: "37",
				want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
			},
			{
				name: "malformed envelope uses rate fallback", status: http.StatusTooManyRequests,
				body: "{", retryAfter: "37",
				want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
			},
		}

		for _, action := range actions {
			for _, test := range cases {
				t.Run(action+"/"+test.name, func(t *testing.T) {
					adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if got := r.URL.Query().Get("Action"); got != action {
							t.Errorf("Action = %q, want %q", got, action)
						}
						w.Header().Set("Retry-After", test.retryAfter)
						w.WriteHeader(test.status)
						if test.body != "" {
							_, _ = w.Write([]byte(test.body))
							return
						}
						writeTestJSON(t, w, map[string]any{
							"RequestId": "request-id", "Code": test.code, "Message": providerMessage,
						})
					}), time.Second)
					provider := &aliyunProvider{adapter: adapter}
					_, err := provider.request(t.Context(), ProviderConfig{Credentials: map[string]string{
						"access_key_id": aliyunAccessKey, "access_key_secret": aliyunSecret,
					}}, map[string]string{"Action": action})
					assertError(t, err, test.want, test.temporary, test.wantRetry,
						aliyunAccessKey, aliyunSecret, providerMessage)
				})
			}
		}
	})

	t.Run("huawei", func(t *testing.T) {
		operations := []struct {
			name   string
			method string
			path   string
		}{
			{name: "create", method: http.MethodPost, path: "/v2.1/zones/zone-id/recordsets"},
			{name: "get", method: http.MethodGet, path: "/v2.1/zones/zone-id/recordsets/record-id"},
			{name: "delete", method: http.MethodDelete, path: "/v2.1/zones/zone-id/recordsets/record-id"},
			{name: "list", method: http.MethodGet, path: "/v2.1/zones/zone-id/recordsets"},
			{name: "zone", method: http.MethodGet, path: "/v2/zones"},
		}
		cases := []struct {
			name       string
			body       string
			code       string
			retryAfter string
			want       ErrorCode
			temporary  bool
			wantRetry  time.Duration
		}{
			{name: "rate status rejected credential", code: "APIGW.0301", want: CodeCredentialsRejected},
			{
				name: "unknown envelope uses rate fallback", code: "DNS.Future.Code", retryAfter: "37",
				want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
			},
			{
				name: "malformed envelope uses rate fallback", body: "{", retryAfter: "37",
				want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second,
			},
		}

		for _, operation := range operations {
			for _, test := range cases {
				t.Run(operation.name+"/"+test.name, func(t *testing.T) {
					adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != operation.method || r.URL.Path != operation.path {
							t.Errorf("request = %s %s, want %s %s", r.Method, r.URL.Path, operation.method, operation.path)
						}
						w.Header().Set("Retry-After", test.retryAfter)
						w.WriteHeader(http.StatusTooManyRequests)
						if test.body != "" {
							_, _ = w.Write([]byte(test.body))
							return
						}
						writeTestJSON(t, w, map[string]any{
							"error_code": test.code, "error_msg": providerMessage,
						})
					}), time.Second)
					provider := &huaweiProvider{adapter: adapter}
					_, err := provider.requestAllowNotFound(t.Context(), ProviderConfig{Credentials: map[string]string{
						"access_key": huaweiAccessKey, "secret_key": huaweiSecret,
						"region": "cn-north-4", "project_id": projectID,
					}}, operation.method, operation.path, "", nil)
					assertError(t, err, test.want, test.temporary, test.wantRetry,
						huaweiAccessKey, huaweiSecret, projectID, providerMessage)
				})
			}
		}
	})
}
