package dnsproviderremote

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestCloudflareProviderErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		want       ErrorCode
		retryAfter string
	}{
		{name: "invalid token", code: 9109, want: CodeCredentialsRejected},
		{name: "authentication error", code: 10000, want: CodeCredentialsRejected},
		{name: "rate limited", code: 1015, want: CodeRateLimited, retryAfter: "23"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", test.retryAfter)
				writeTestJSON(t, w, map[string]any{
					"success": false,
					"errors":  []map[string]any{{"code": test.code, "message": "sensitive upstream response"}},
				})
			}), time.Second)
			_, err := (&cloudflareProvider{adapter: adapter}).request(
				context.Background(), http.MethodGet, "/zones", "secret-token", nil,
			)
			assertRemoteError(t, err, test.want)
			if test.want == CodeRateLimited {
				assertRetryAfter(t, err, 23*time.Second)
			}
		})
	}
}

func TestAliyunProviderErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		want       ErrorCode
		retryAfter string
	}{
		{name: "authentication", code: "Forbidden.RAM", want: CodeCredentialsRejected},
		{name: "throttling", code: "Throttling.User", want: CodeRateLimited, retryAfter: "31"},
		{name: "missing record", code: "InvalidRecordId.NotFound", want: CodeRecordNotFound},
		{name: "wrong owner", code: "DomainRecordNotBelongToUser", want: CodeRecordNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", test.retryAfter)
				writeTestJSON(t, w, map[string]any{
					"RequestId": "request-id", "Code": test.code, "Message": "sensitive upstream response",
				})
			}), time.Second)
			_, err := (&aliyunProvider{adapter: adapter}).request(context.Background(), ProviderConfig{
				Credentials: map[string]string{"access_key_id": "access-key", "access_key_secret": "secret-key"},
			}, map[string]string{"Action": "DescribeDomainRecordInfo", "RecordId": "record-id"})
			assertRemoteError(t, err, test.want)
			if test.want == CodeRateLimited {
				assertRetryAfter(t, err, 31*time.Second)
			}
		})
	}
}

func TestHuaweiAuthenticationEnvelope(t *testing.T) {
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeTestJSON(t, w, map[string]any{
			"error_code": "APIGW.0301", "error_msg": "sensitive upstream response",
		})
	}), time.Second)
	_, err := (&huaweiProvider{adapter: adapter}).requestAllowNotFound(
		context.Background(),
		ProviderConfig{Credentials: map[string]string{
			"access_key": "access", "secret_key": "secret", "region": "cn-north-4",
			"project_id": "0123456789abcdef0123456789abcdef",
		}},
		http.MethodGet,
		"/v2.1/zones/zone/recordsets/record",
		"",
		nil,
	)
	assertRemoteError(t, err, CodeCredentialsRejected)
}

func TestDNSPodProviderErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		want       ErrorCode
		temporary  bool
		retryAfter string
	}{
		{name: "login failed", code: "-1", want: CodeCredentialsRejected},
		{name: "quota exceeded", code: "-2", want: CodeRateLimited, temporary: true, retryAfter: "41"},
		{name: "feature paused", code: "-99", want: CodeUnavailable, temporary: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", test.retryAfter)
				writeTestJSON(t, w, map[string]any{
					"status": map[string]any{"code": test.code, "message": "sensitive upstream response"},
				})
			}), time.Second)
			_, err := (&dnsPodProvider{adapter: adapter}).request(context.Background(), ProviderConfig{
				Credentials: map[string]string{"dp_id": "12345", "dp_key": "secret-key"},
			}, "/Record.Info", url.Values{"domain": {testZone}, "record_id": {"record-id"}})
			assertRemoteError(t, err, test.want)
			var remoteError *Error
			if !errors.As(err, &remoteError) || remoteError.Temporary != test.temporary {
				t.Fatalf("error = %+v, temporary want %v", err, test.temporary)
			}
			if test.want == CodeRateLimited {
				assertRetryAfter(t, err, 41*time.Second)
			}
		})
	}
}

func TestDNSComUnknownBusinessCodeFailsClosed(t *testing.T) {
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"code": 9876, "message": "sensitive upstream response", "data": map[string]any{},
		})
	}), time.Second)
	_, err := (&dnsComProvider{adapter: adapter}).request(context.Background(), ProviderConfig{
		Credentials: map[string]string{"api_key": "api-key", "api_secret": "api-secret"},
	}, "/api/record/getOne/", map[string]string{"domain": "zone-id", "record_id": "record-id"})
	assertRemoteError(t, err, CodeInvalidResponse)
}

func TestDNSLAInternalBusinessCodeIsRetryable(t *testing.T) {
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"code": http.StatusInternalServerError, "message": "sensitive upstream response", "data": nil,
		})
	}), time.Second)
	_, err := (&dnsLAProvider{adapter: adapter}).request(context.Background(), ProviderConfig{
		Credentials: map[string]string{"api_id": "api-id", "api_secret": "api-secret"},
	}, http.MethodGet, "/api/domain?domain=example.test", nil)
	assertRemoteError(t, err, CodeUnavailable)
	var remoteError *Error
	if !errors.As(err, &remoteError) || !remoteError.Temporary {
		t.Fatalf("error = %+v, want temporary", err)
	}
}

func TestDNSComRequestDoesNotMutateCallerParametersWithCredentials(t *testing.T) {
	parameters := map[string]string{"domain": "zone-id", "record_id": "record-id"}
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("api_key") != "api-key" || query.Get("sign") == "" || query.Get("timestamp") == "" {
			t.Fatalf("signed query missing expected fields: %v", query)
		}
		writeTestJSON(t, w, map[string]any{"code": 0, "data": map[string]any{}})
	}), time.Second)
	_, err := (&dnsComProvider{adapter: adapter}).request(context.Background(), ProviderConfig{
		Credentials: map[string]string{"api_key": "api-key", "api_secret": "api-secret"},
	}, "/api/record/getOne/", parameters)
	if err != nil {
		t.Fatalf("request() error=%v", err)
	}
	if len(parameters) != 2 || parameters["domain"] != "zone-id" || parameters["record_id"] != "record-id" {
		t.Fatalf("caller parameters mutated: %v", parameters)
	}
}

func TestUnprovenHTTPNotFoundFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, *Adapter) error
	}{
		{
			name: "dnspod",
			call: func(ctx context.Context, adapter *Adapter) error {
				_, err := (&dnsPodProvider{adapter: adapter}).request(ctx, ProviderConfig{
					Credentials: map[string]string{"dp_id": "12345", "dp_key": "secret-key"},
				}, "/Record.Info", url.Values{"domain": {testZone}, "record_id": {"record-id"}})
				return err
			},
		},
		{
			name: "dnscom",
			call: func(ctx context.Context, adapter *Adapter) error {
				_, err := (&dnsComProvider{adapter: adapter}).request(ctx, ProviderConfig{
					Credentials: map[string]string{"api_key": "api-key", "api_secret": "api-secret"},
				}, "/api/record/getOne/", map[string]string{"domain": "zone-id", "record_id": "record-id"})
				return err
			},
		},
		{
			name: "dnsla",
			call: func(ctx context.Context, adapter *Adapter) error {
				_, err := (&dnsLAProvider{adapter: adapter}).request(ctx, ProviderConfig{
					Credentials: map[string]string{"api_id": "api-id", "api_secret": "api-secret"},
				}, http.MethodDelete, "/api/record?id=record-id", nil)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}), time.Second)
			assertRemoteError(t, test.call(context.Background(), adapter), CodeInvalidResponse)
		})
	}
}

func TestDNSLAInconsistentExactPageFailsClosed(t *testing.T) {
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{"code": 200, "data": map[string]any{
			"total": 0,
			"results": []map[string]any{{
				"id": "different-record", "domainId": "zone-id", "host": testRelative,
				"type": 16, "data": testValue,
			}},
		}})
	}), time.Second)
	_, _, err := (&dnsLAProvider{adapter: adapter}).get(context.Background(), ProviderConfig{
		Credentials: map[string]string{"api_id": "api-id", "api_secret": "api-secret"},
	}, recordHandle{
		Provider: providerDNSLA, Zone: testZone, ZoneID: "zone-id", RecordID: "record-id", Owner: testOwner,
	}, testValue)
	assertRemoteError(t, err, CodeInvalidResponse)
}

func assertRetryAfter(t *testing.T, err error, want time.Duration) {
	t.Helper()
	var remoteError *Error
	if !errors.As(err, &remoteError) || remoteError.RetryAfter != want || !remoteError.Temporary {
		t.Fatalf("error = %+v, retry after want %s", err, want)
	}
}
