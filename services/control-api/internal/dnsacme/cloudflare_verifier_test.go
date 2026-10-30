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

func TestCloudflareProviderVerifierActiveToken(t *testing.T) {
	const token = "cloudflare-test-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/user/tokens/verify" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if authorization := r.Header.Get("Authorization"); authorization != "Bearer "+token {
			t.Errorf("Authorization = %q", authorization)
		}
		if accept := r.Header.Get("Accept"); accept != "application/json" {
			t.Errorf("Accept = %q", accept)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"token-id","status":"active"},"messages":[]}`))
	}))
	t.Cleanup(server.Close)

	verifier := newCloudflareProviderVerifier(server.URL, server.Client(), time.Second)
	if err := verifier.Verify(context.Background(), "cloudflare", token); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestCloudflareProviderVerifierClassifiesResponses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "inactive", status: http.StatusOK, body: `{"success":true,"result":{"status":"expired"}}`, want: ErrProviderTokenInactive},
		{name: "unsuccessful", status: http.StatusOK, body: `{"success":false,"result":{"status":"active"}}`, want: ErrProviderCredentialsRejected},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"secret":"do-not-return"}`, want: ErrProviderCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, want: ErrProviderCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "120", want: ErrProviderVerificationRateLimited, wantRetry: "120"},
		{name: "invalid retry after", status: http.StatusTooManyRequests, retryAfter: "not-valid", want: ErrProviderVerificationRateLimited},
		{name: "unavailable", status: http.StatusBadGateway, want: ErrProviderVerificationUnavailable},
		{name: "unexpected", status: http.StatusTeapot, want: ErrProviderVerificationInvalidResponse},
		{name: "bad json", status: http.StatusOK, body: `{`, want: ErrProviderVerificationInvalidResponse},
		{name: "trailing json", status: http.StatusOK, body: `{"success":true,"result":{"status":"active"}} {}`, want: ErrProviderVerificationInvalidResponse},
		{name: "active missing token id", status: http.StatusOK, body: `{"success":true,"result":{"status":"active"},"messages":["do-not-return"]}`, want: ErrProviderVerificationInvalidResponse},
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
			verifier := newCloudflareProviderVerifier(server.URL, server.Client(), time.Second)
			err := verifier.Verify(context.Background(), "cloudflare", "private-token")
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retryAfter, test.wantRetry)
			}
			if strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "do-not-return") {
				t.Fatalf("error leaked remote secret: %q", err)
			}
		})
	}
}

func TestCloudflareProviderVerifierRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active"},"padding":"` +
			strings.Repeat("x", cloudflareVerifyBodySize) + `"}`))
	}))
	t.Cleanup(server.Close)
	verifier := newCloudflareProviderVerifier(server.URL, server.Client(), time.Second)
	if err := verifier.Verify(context.Background(), "cloudflare", "token"); !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestCloudflareProviderVerifierTimeoutAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	verifier := newCloudflareProviderVerifier(server.URL, server.Client(), 20*time.Millisecond)
	if err := verifier.Verify(context.Background(), "cloudflare", "token"); !errors.Is(err, ErrProviderVerificationTimeout) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.Verify(ctx, "cloudflare", "token"); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation error = %v", err)
	}
}

func TestCloudflareProviderVerifierDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/followed" {
			followed.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
			return
		}
		http.Redirect(w, r, "/followed", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	verifier := newCloudflareProviderVerifier(server.URL, server.Client(), time.Second)
	if err := verifier.Verify(context.Background(), "cloudflare", "token"); !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("redirect error = %v", err)
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was called %d times", followed.Load())
	}
}

func TestCloudflareProviderVerifierRejectsUnsupportedProviderWithoutRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)
	verifier := newCloudflareProviderVerifier(server.URL, server.Client(), time.Second)
	if err := verifier.Verify(context.Background(), "aliyun", "token"); !errors.Is(err, ErrProviderVerificationUnsupported) {
		t.Fatalf("Verify() error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("unsupported provider made %d requests", calls.Load())
	}
}

func TestCloudflareProductionVerifierUsesFixedEndpoint(t *testing.T) {
	verifier := NewCloudflareProviderVerifier()
	if verifier.baseURL != cloudflareAPIBaseURL {
		t.Fatalf("baseURL = %q", verifier.baseURL)
	}
}
