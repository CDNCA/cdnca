package dnsacme

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	huaweiTestProjectID = "0123456789abcdef0123456789abcdef"
	huaweiTestAccessKey = "test-huawei-access-key"
	huaweiTestSecretKey = "test-huawei-secret-key"
)

func TestHuaweiSignerMatchesOfficialSDKVector(t *testing.T) {
	const timestamp = "20060102T150405Z"
	const canonicalRequest = "GET\n/path/\nlimit=1\nx-sdk-date:20060102T150405Z\n\nx-sdk-date\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	const stringToSign = "SDK-HMAC-SHA256\n20060102T150405Z\n" +
		"85c3b7730f308aee452b16138a42a914397e43a8f0d732dfa521c0ef2afa98a4"
	const authorization = "SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=x-sdk-date, " +
		"Signature=5a2ce64c865e0e6046321c6f3d5a77ba8413eeaf355c3166c03d58d02ac79624"

	signed := signHuaweiRequest(
		http.MethodGet,
		"/path/",
		"limit=1",
		map[string]string{"X-Sdk-Date": timestamp},
		nil,
		"AccessKey",
		"SecretKey",
		timestamp,
	)
	if signed.CanonicalRequest != canonicalRequest {
		t.Fatalf("CanonicalRequest = %q, want %q", signed.CanonicalRequest, canonicalRequest)
	}
	if signed.StringToSign != stringToSign {
		t.Fatalf("StringToSign = %q, want %q", signed.StringToSign, stringToSign)
	}
	if signed.Authorization != authorization {
		t.Fatalf("Authorization = %q, want %q", signed.Authorization, authorization)
	}
}

func TestHuaweiProviderVerifierSignsListPublicZones(t *testing.T) {
	const timestamp = "20260722T030405Z"
	const authorization = "SDK-HMAC-SHA256 Access=test-huawei-access-key, " +
		"SignedHeaders=host;x-project-id;x-sdk-date, " +
		"Signature=71dbfda119617115c8d38126fe3f9c7cf7f9695975e5b7d14b9bf19297dec17a"
	fixedTime := time.Date(2026, time.July, 22, 3, 4, 5, 987654321, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != huaweiVerifyRequestPath || r.URL.RawQuery != huaweiVerifyQuery {
			t.Errorf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if r.Host != "dns.cn-north-4.myhuaweicloud.com" {
			t.Errorf("Host = %q", r.Host)
		}
		if got := r.Header.Get("X-Project-Id"); got != huaweiTestProjectID {
			t.Errorf("X-Project-Id = %q", got)
		}
		if got := r.Header.Get("X-Sdk-Date"); got != timestamp {
			t.Errorf("X-Sdk-Date = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != authorization {
			t.Errorf("Authorization = %q, want %q", got, authorization)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		_, _ = w.Write([]byte(`{"zones":[],"metadata":{"total_count":0}}`))
	}))
	t.Cleanup(server.Close)

	verifier := newHuaweiProviderVerifier(server.URL, server.Client(), time.Second, func() time.Time { return fixedTime })
	if err := verifier.Verify(
		context.Background(),
		"cn-north-4",
		huaweiTestProjectID,
		huaweiTestAccessKey,
		huaweiTestSecretKey,
	); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestHuaweiProviderVerifierClassifiesResponses(t *testing.T) {
	const upstreamSecret = "sensitive upstream response"
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"error_msg":"sensitive upstream response"}`, want: ErrProviderCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: `{"error_msg":"sensitive upstream response"}`, want: ErrProviderCredentialsRejected},
		{name: "authentication envelope", status: http.StatusBadRequest, body: `{"error_code":"APIGW.0301","error_msg":"sensitive upstream response"}`, want: ErrProviderCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "120", want: ErrProviderVerificationRateLimited, wantRetry: "120"},
		{name: "rate limited invalid retry", status: http.StatusTooManyRequests, retryAfter: upstreamSecret, want: ErrProviderVerificationRateLimited},
		{name: "unavailable", status: http.StatusBadGateway, body: `{"error_msg":"sensitive upstream response"}`, want: ErrProviderVerificationUnavailable},
		{name: "unexpected status", status: http.StatusTeapot, body: `{"error_code":"DNS.0001","error_msg":"sensitive upstream response"}`, want: ErrProviderVerificationInvalidResponse},
		{name: "bad json", status: http.StatusOK, body: `{`, want: ErrProviderVerificationInvalidResponse},
		{name: "trailing json", status: http.StatusOK, body: `{"zones":[]} {}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing zones", status: http.StatusOK, body: `{"metadata":{"total_count":0}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null zones", status: http.StatusOK, body: `{"zones":null}`, want: ErrProviderVerificationInvalidResponse},
		{name: "invalid zones", status: http.StatusOK, body: `{"zones":{}}`, want: ErrProviderVerificationInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.retryAfter != "" {
					w.Header().Set("Retry-After", test.retryAfter)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)
			verifier := newHuaweiTestVerifier(server)
			err := verifier.Verify(
				context.Background(),
				"cn-north-4",
				huaweiTestProjectID,
				huaweiTestAccessKey,
				huaweiTestSecretKey,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retryAfter, test.wantRetry)
			}
			for _, sensitive := range []string{huaweiTestAccessKey, huaweiTestSecretKey, upstreamSecret, "Authorization"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
				}
			}
		})
	}
}

func TestHuaweiProviderVerifierValidatesListPublicZonesResponse(t *testing.T) {
	const upstreamSecret = "sensitive upstream response"
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "zero zones", body: `{"zones":[],"metadata":{"total_count":0}}`},
		{name: "partial page", body: `{"zones":[{}],"metadata":{"total_count":2}}`},
		{name: "missing metadata", body: `{"zones":[]}`, wantErr: true},
		{name: "missing total count", body: `{"zones":[],"metadata":{}}`, wantErr: true},
		{name: "negative total count", body: `{"zones":[],"metadata":{"total_count":-1}}`, wantErr: true},
		{name: "zero count with zone", body: `{"zones":[{}],"metadata":{"total_count":0}}`, wantErr: true},
		{name: "nonzero count with empty first page", body: `{"zones":[],"metadata":{"total_count":1}}`, wantErr: true},
		{name: "page exceeds total count", body: `{"zones":[{},{}],"metadata":{"total_count":1}}`, wantErr: true},
		{name: "null zone", body: `{"zones":[null],"metadata":{"total_count":1}}`, wantErr: true},
		{name: "non-object zone", body: `{"zones":["sensitive upstream response"],"metadata":{"total_count":1}}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)
			err := newHuaweiTestVerifier(server).Verify(
				context.Background(),
				"cn-north-4",
				huaweiTestProjectID,
				huaweiTestAccessKey,
				huaweiTestSecretKey,
			)
			if test.wantErr {
				if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
					t.Fatalf("Verify() error = %v, want %v", err, ErrProviderVerificationInvalidResponse)
				}
				for _, sensitive := range []string{huaweiTestAccessKey, huaweiTestSecretKey, upstreamSecret} {
					if strings.Contains(err.Error(), sensitive) {
						t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestHuaweiProviderVerifierRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"zones":[],"padding":"` + strings.Repeat("x", huaweiVerifyBodySize) + `"}`))
	}))
	t.Cleanup(server.Close)
	err := newHuaweiTestVerifier(server).Verify(
		context.Background(), "cn-north-4", huaweiTestProjectID, huaweiTestAccessKey, huaweiTestSecretKey,
	)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestHuaweiProviderVerifierTimeoutAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(server.Close)
	verifier := newHuaweiProviderVerifier(server.URL, server.Client(), 20*time.Millisecond, time.Now)
	if err := verifier.Verify(
		context.Background(), "cn-north-4", huaweiTestProjectID, huaweiTestAccessKey, huaweiTestSecretKey,
	); !errors.Is(err, ErrProviderVerificationTimeout) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.Verify(
		ctx, "cn-north-4", huaweiTestProjectID, huaweiTestAccessKey, huaweiTestSecretKey,
	); err != context.Canceled {
		t.Fatalf("caller cancellation error = %v", err)
	}
}

func TestHuaweiProviderVerifierDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/followed" {
			followed.Add(1)
			_, _ = w.Write([]byte(`{"zones":[]}`))
			return
		}
		http.Redirect(w, r, "/followed", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	err := newHuaweiTestVerifier(server).Verify(
		context.Background(), "cn-north-4", huaweiTestProjectID, huaweiTestAccessKey, huaweiTestSecretKey,
	)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("redirect error = %v", err)
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was called %d times", followed.Load())
	}
}

func TestHuaweiProviderVerifierClassifiesNetworkFailureWithoutLeak(t *testing.T) {
	client := &http.Client{Transport: failingHuaweiTransport{}}
	verifier := newHuaweiProviderVerifier("https://example.invalid", client, time.Second, time.Now)
	err := verifier.Verify(
		context.Background(), "cn-north-4", huaweiTestProjectID, huaweiTestAccessKey, huaweiTestSecretKey,
	)
	if !errors.Is(err, ErrProviderVerificationUnavailable) {
		t.Fatalf("Verify() error = %v", err)
	}
	for _, sensitive := range []string{huaweiTestAccessKey, huaweiTestSecretKey, "sensitive transport detail"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
		}
	}
}

func TestHuaweiProductionVerifierUsesFixedEndpointAllowlist(t *testing.T) {
	verifier := NewHuaweiProviderVerifier()
	if verifier.testBaseURL != "" {
		t.Fatalf("production testBaseURL = %q", verifier.testBaseURL)
	}
	if verifier.timeout != 5*time.Second {
		t.Fatalf("production timeout = %s", verifier.timeout)
	}
	want := map[string]string{
		"cn-north-4":     "dns.cn-north-4.myhuaweicloud.com",
		"ap-southeast-3": "dns.ap-southeast-3.myhuaweicloud.com",
	}
	for region, host := range want {
		got, ok := huaweiDNSHost(region)
		if !ok || got != host || !strings.HasSuffix(host, ".myhuaweicloud.com") {
			t.Fatalf("Huawei endpoint for %q = %q, %t", region, got, ok)
		}
	}
	if host, ok := huaweiDNSHost("dns.example.invalid"); ok || host != "" {
		t.Fatalf("arbitrary Huawei region resolved to %q", host)
	}
}

func newHuaweiTestVerifier(server *httptest.Server) *HuaweiProviderVerifier {
	return newHuaweiProviderVerifier(
		server.URL,
		server.Client(),
		time.Second,
		func() time.Time { return time.Date(2026, time.July, 22, 3, 4, 5, 0, time.UTC) },
	)
}

type failingHuaweiTransport struct{}

func (failingHuaweiTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("sensitive transport detail")
}
