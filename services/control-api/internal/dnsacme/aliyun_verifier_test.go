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

func TestAliyunProviderVerifierSignsDescribeDomains(t *testing.T) {
	const expectedQuery = "AccessKeyId=test-access-key&Action=DescribeDomains&Format=JSON&" +
		"SignatureMethod=HMAC-SHA1&SignatureNonce=nonce-123&SignatureVersion=1.0&" +
		"Timestamp=2026-07-22T03%3A04%3A05Z&Version=2015-01-09&" +
		"Signature=ds2CO9GpxNEdQzZRKiLG6Bd0aX8%3D"
	fixedTime := time.Date(2026, time.July, 22, 3, 4, 5, 987654321, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.URL.RawQuery != expectedQuery {
			t.Errorf("RawQuery = %q, want %q", r.URL.RawQuery, expectedQuery)
		}
		if accept := r.Header.Get("Accept"); accept != "application/json" {
			t.Errorf("Accept = %q", accept)
		}
		_, _ = w.Write([]byte(`{"RequestId":"request-id","TotalCount":0,"Domains":{"Domain":[]}}`))
	}))
	t.Cleanup(server.Close)

	verifier := newAliyunProviderVerifier(
		server.URL,
		server.Client(),
		time.Second,
		func() time.Time { return fixedTime },
		func() string { return "nonce-123" },
	)
	if err := verifier.Verify(context.Background(), "test-access-key", "test-access-secret"); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestAliyunPercentEncodeUsesRFC3986(t *testing.T) {
	const input = "AZaz09-_.~ /+*"
	const want = "AZaz09-_.~%20%2F%2B%2A"
	if got := aliyunPercentEncode(input); got != want {
		t.Fatalf("aliyunPercentEncode(%q) = %q, want %q", input, got, want)
	}
}

func TestAliyunProviderVerifierClassifiesResponses(t *testing.T) {
	const accessKeyID = "sensitive-access-key-id"
	const accessKeySecret = "sensitive-access-key-secret"
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "access key rejected", status: http.StatusBadRequest, body: `{"RequestId":"request-id","Code":"InvalidAccessKeyId.NotFound","Message":"sensitive upstream body"}`, want: ErrProviderCredentialsRejected},
		{name: "signature rejected", status: http.StatusBadRequest, body: `{"RequestId":"request-id","Code":"SignatureDoesNotMatch","Message":"sensitive upstream body"}`, want: ErrProviderCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: `{"Message":"sensitive upstream body"}`, want: ErrProviderCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "120", want: ErrProviderVerificationRateLimited, wantRetry: "120"},
		{name: "rate limited invalid retry", status: http.StatusTooManyRequests, retryAfter: "sensitive upstream body", want: ErrProviderVerificationRateLimited},
		{name: "unavailable", status: http.StatusBadGateway, body: `{"Message":"sensitive upstream body"}`, want: ErrProviderVerificationUnavailable},
		{name: "rpc rate limited", status: http.StatusBadRequest, body: `{"RequestId":"request-id","Code":"Throttling.User","Message":"sensitive upstream body"}`, retryAfter: "60", want: ErrProviderVerificationRateLimited, wantRetry: "60"},
		{name: "unexpected", status: http.StatusTeapot, body: `{"RequestId":"request-id","Code":"InvalidParameter","Message":"sensitive upstream body"}`, want: ErrProviderVerificationInvalidResponse},
		{name: "bad json", status: http.StatusOK, body: `{`, want: ErrProviderVerificationInvalidResponse},
		{name: "trailing json", status: http.StatusOK, body: `{"RequestId":"request-id"} {}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing request id", status: http.StatusOK, body: `{}`, want: ErrProviderVerificationInvalidResponse},
		{name: "error envelope with ok status", status: http.StatusOK, body: `{"RequestId":"request-id","Code":"SignatureDoesNotMatch","Message":"sensitive upstream body"}`, want: ErrProviderCredentialsRejected},
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
			verifier := newAliyunTestVerifier(server)
			err := verifier.Verify(context.Background(), accessKeyID, accessKeySecret)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retryAfter, test.wantRetry)
			}
			for _, secret := range []string{accessKeyID, accessKeySecret, "sensitive upstream body"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked sensitive value %q: %q", secret, err)
				}
			}
		})
	}
}

func TestAliyunProviderVerifierValidatesDescribeDomainsResponse(t *testing.T) {
	const (
		accessKeyID     = "sensitive-access-key-id"
		accessKeySecret = "sensitive-access-key-secret"
		upstreamSecret  = "sensitive upstream body"
	)
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "zero domains", body: `{"RequestId":"request-id","TotalCount":0,"Domains":{"Domain":[]}}`},
		{name: "partial page", body: `{"RequestId":"request-id","TotalCount":2,"Domains":{"Domain":[{}]}}`},
		{name: "missing total count", body: `{"RequestId":"request-id","Domains":{"Domain":[]}}`, wantErr: true},
		{name: "negative total count", body: `{"RequestId":"request-id","TotalCount":-1,"Domains":{"Domain":[]}}`, wantErr: true},
		{name: "missing domains", body: `{"RequestId":"request-id","TotalCount":0}`, wantErr: true},
		{name: "missing domain list", body: `{"RequestId":"request-id","TotalCount":0,"Domains":{}}`, wantErr: true},
		{name: "null domain list", body: `{"RequestId":"request-id","TotalCount":0,"Domains":{"Domain":null}}`, wantErr: true},
		{name: "zero count with domain", body: `{"RequestId":"request-id","TotalCount":0,"Domains":{"Domain":[{}]}}`, wantErr: true},
		{name: "nonzero count with empty first page", body: `{"RequestId":"request-id","TotalCount":1,"Domains":{"Domain":[]}}`, wantErr: true},
		{name: "page exceeds total count", body: `{"RequestId":"request-id","TotalCount":1,"Domains":{"Domain":[{},{}]}}`, wantErr: true},
		{name: "null domain", body: `{"RequestId":"request-id","TotalCount":1,"Domains":{"Domain":[null]}}`, wantErr: true},
		{name: "non-object domain", body: `{"RequestId":"request-id","TotalCount":1,"Domains":{"Domain":["sensitive upstream body"]}}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)
			err := newAliyunTestVerifier(server).Verify(context.Background(), accessKeyID, accessKeySecret)
			if test.wantErr {
				if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
					t.Fatalf("Verify() error = %v, want %v", err, ErrProviderVerificationInvalidResponse)
				}
				for _, sensitive := range []string{accessKeyID, accessKeySecret, upstreamSecret} {
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

func TestAliyunProviderVerifierRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"RequestId":"request-id","padding":"` +
			strings.Repeat("x", aliyunVerifyBodySize) + `"}`))
	}))
	t.Cleanup(server.Close)
	if err := newAliyunTestVerifier(server).Verify(context.Background(), "access-key", "secret"); !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestAliyunProviderVerifierTimeoutAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(server.Close)
	verifier := newAliyunProviderVerifier(server.URL, server.Client(), 20*time.Millisecond, time.Now, func() string { return "nonce" })
	if err := verifier.Verify(context.Background(), "access-key", "secret"); !errors.Is(err, ErrProviderVerificationTimeout) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.Verify(ctx, "access-key", "secret"); err != context.Canceled {
		t.Fatalf("caller cancellation error = %v", err)
	}
}

func TestAliyunProviderVerifierClassifiesNetworkFailureWithoutLeak(t *testing.T) {
	const accessKeyID = "sensitive-access-key-id"
	const accessKeySecret = "sensitive-access-key-secret"
	client := &http.Client{Transport: failingAliyunTransport{}}
	verifier := newAliyunProviderVerifier(
		"https://example.invalid",
		client,
		time.Second,
		time.Now,
		func() string { return "nonce" },
	)
	err := verifier.Verify(context.Background(), accessKeyID, accessKeySecret)
	if !errors.Is(err, ErrProviderVerificationUnavailable) {
		t.Fatalf("Verify() error = %v", err)
	}
	for _, sensitive := range []string{accessKeyID, accessKeySecret, "sensitive transport detail"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
		}
	}
}

func TestAliyunProviderVerifierDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/followed" {
			followed.Add(1)
			_, _ = w.Write([]byte(`{"RequestId":"request-id"}`))
			return
		}
		http.Redirect(w, r, "/followed", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	if err := newAliyunTestVerifier(server).Verify(context.Background(), "access-key", "secret"); !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("redirect error = %v", err)
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was called %d times", followed.Load())
	}
}

func TestAliyunProductionVerifierUsesFixedHTTPSEndpoint(t *testing.T) {
	verifier := NewAliyunProviderVerifier()
	if verifier.baseURL != aliyunDNSAPIEndpoint || !strings.HasPrefix(verifier.baseURL, "https://") {
		t.Fatalf("baseURL = %q", verifier.baseURL)
	}
}

func newAliyunTestVerifier(server *httptest.Server) *AliyunProviderVerifier {
	return newAliyunProviderVerifier(
		server.URL,
		server.Client(),
		time.Second,
		func() time.Time { return time.Date(2026, time.July, 22, 3, 4, 5, 0, time.UTC) },
		func() string { return "nonce" },
	)
}

type failingAliyunTransport struct{}

func (failingAliyunTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("sensitive transport detail")
}
