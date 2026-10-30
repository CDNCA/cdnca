package dnsacme

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	dnspodTestID     = "12345"
	dnspodTestKey    = "test-dnspod-key"
	dnspodTestSecret = "sensitive upstream response"
)

func TestDNSPodProviderVerifierUsesCanonicalTokenForm(t *testing.T) {
	const expectedBody = "error_on_empty=no&format=json&lang=en&login_token=12345%2Ctest-dnspod-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/User.Detail" || r.URL.RawQuery != "" {
			t.Errorf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if r.Host != dnspodVerifyHost {
			t.Errorf("Host = %q", r.Host)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != dnspodVerifyUserAgent {
			t.Errorf("User-Agent = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if string(body) != expectedBody {
			t.Errorf("body = %q, want %q", body, expectedBody)
		}
		_, _ = w.Write([]byte(`{"status":{"code":"1"},"info":{"user":{}}}`))
	}))
	t.Cleanup(server.Close)

	if err := newDNSPodTestVerifier(server).Verify(context.Background(), dnspodTestID, dnspodTestKey); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSPodProviderVerifierClassifiesResponses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: dnspodTestSecret, want: ErrProviderCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: dnspodTestSecret, want: ErrProviderCredentialsRejected},
		{name: "login failed", status: http.StatusOK, body: `{"status":{"code":"-1","message":"sensitive upstream response"}}`, want: ErrProviderCredentialsRejected},
		{name: "permission denied", status: http.StatusOK, body: `{"status":{"code":"-7","message":"sensitive upstream response"}}`, want: ErrProviderCredentialsRejected},
		{name: "temporary block", status: http.StatusOK, body: `{"status":{"code":"-8","message":"sensitive upstream response"}}`, want: ErrProviderCredentialsRejected},
		{name: "remote login denied", status: http.StatusOK, body: `{"status":{"code":"85","message":"sensitive upstream response"}}`, want: ErrProviderCredentialsRejected},
		{name: "http rate limited", status: http.StatusTooManyRequests, retryAfter: "120", body: dnspodTestSecret, want: ErrProviderVerificationRateLimited, wantRetry: "120"},
		{name: "http rate limited invalid retry", status: http.StatusTooManyRequests, retryAfter: dnspodTestSecret, want: ErrProviderVerificationRateLimited},
		{name: "api rate limited", status: http.StatusOK, retryAfter: "Thu, 23 Jul 2026 12:00:00 GMT", body: `{"status":{"code":"-2"}}`, want: ErrProviderVerificationRateLimited, wantRetry: "Thu, 23 Jul 2026 12:00:00 GMT"},
		{name: "api unavailable", status: http.StatusOK, body: `{"status":{"code":"-99"}}`, want: ErrProviderVerificationUnavailable},
		{name: "http unavailable", status: http.StatusBadGateway, body: dnspodTestSecret, want: ErrProviderVerificationUnavailable},
		{name: "unexpected status", status: http.StatusTeapot, body: `{"status":{"code":"1"},"info":{"user":{}}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "unknown code", status: http.StatusOK, body: `{"status":{"code":"2","message":"sensitive upstream response"}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "bad json", status: http.StatusOK, body: `{`, want: ErrProviderVerificationInvalidResponse},
		{name: "trailing json", status: http.StatusOK, body: `{"status":{"code":"1"},"info":{}} {}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing status", status: http.StatusOK, body: `{"info":{}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing status code", status: http.StatusOK, body: `{"status":{},"info":{}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing info", status: http.StatusOK, body: `{"status":{"code":"1"}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null info", status: http.StatusOK, body: `{"status":{"code":"1"},"info":null}`, want: ErrProviderVerificationInvalidResponse},
		{name: "invalid info", status: http.StatusOK, body: `{"status":{"code":"1"},"info":[]}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing user", status: http.StatusOK, body: `{"status":{"code":"1"},"info":{}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null user", status: http.StatusOK, body: `{"status":{"code":"1"},"info":{"user":null}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "invalid user", status: http.StatusOK, body: `{"status":{"code":"1"},"info":{"user":[]}}`, want: ErrProviderVerificationInvalidResponse},
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
			err := newDNSPodTestVerifier(server).Verify(context.Background(), dnspodTestID, dnspodTestKey)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retryAfter, test.wantRetry)
			}
			for _, sensitive := range []string{dnspodTestID, dnspodTestKey, dnspodTestSecret, "login_token"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
				}
			}
		})
	}
}

func TestDNSPodProviderVerifierRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":{"code":"1"},"info":{"padding":"` + strings.Repeat("x", dnspodVerifyBodySize) + `"}}`))
	}))
	t.Cleanup(server.Close)
	err := newDNSPodTestVerifier(server).Verify(context.Background(), dnspodTestID, dnspodTestKey)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSPodProviderVerifierTimeoutAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(server.Close)
	verifier := newDNSPodProviderVerifier(server.URL, server.Client(), 20*time.Millisecond)
	if err := verifier.Verify(context.Background(), dnspodTestID, dnspodTestKey); !errors.Is(err, ErrProviderVerificationTimeout) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.Verify(ctx, dnspodTestID, dnspodTestKey); err != context.Canceled {
		t.Fatalf("caller cancellation error = %v", err)
	}
}

func TestDNSPodProviderVerifierDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/followed" {
			followed.Add(1)
			_, _ = w.Write([]byte(`{"status":{"code":"1"},"info":{"user":{}}}`))
			return
		}
		http.Redirect(w, r, "/followed", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	err := newDNSPodTestVerifier(server).Verify(context.Background(), dnspodTestID, dnspodTestKey)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("redirect error = %v", err)
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was called %d times", followed.Load())
	}
}

func TestDNSPodProviderVerifierClassifiesNetworkFailureWithoutLeak(t *testing.T) {
	client := &http.Client{Transport: failingDNSPodTransport{}}
	verifier := newDNSPodProviderVerifier("https://example.invalid/User.Detail", client, time.Second)
	err := verifier.Verify(context.Background(), dnspodTestID, dnspodTestKey)
	if !errors.Is(err, ErrProviderVerificationUnavailable) {
		t.Fatalf("Verify() error = %v", err)
	}
	for _, sensitive := range []string{dnspodTestID, dnspodTestKey, "sensitive transport detail"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
		}
	}
}

func TestDNSPodProductionVerifierUsesFixedHTTPSUserDetailEndpoint(t *testing.T) {
	verifier := NewDNSPodProviderVerifier()
	if verifier.testEndpoint != "" {
		t.Fatalf("production testEndpoint = %q", verifier.testEndpoint)
	}
	if verifier.timeout != 5*time.Second {
		t.Fatalf("production timeout = %s", verifier.timeout)
	}
	if dnspodVerifyEndpoint != "https://dnsapi.cn/User.Detail" {
		t.Fatalf("production endpoint = %q", dnspodVerifyEndpoint)
	}
}

func newDNSPodTestVerifier(server *httptest.Server) *DNSPodProviderVerifier {
	return newDNSPodProviderVerifier(server.URL+"/User.Detail", server.Client(), time.Second)
}

type failingDNSPodTransport struct{}

func (failingDNSPodTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("sensitive transport detail")
}
