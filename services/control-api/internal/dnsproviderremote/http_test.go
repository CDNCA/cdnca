package dnsproviderremote

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedHTTPFailureClassification(t *testing.T) {
	const upstreamSecret = "upstream-sensitive-response"
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       ErrorCode
		wantRetry  time.Duration
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: upstreamSecret, want: CodeCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: upstreamSecret, want: CodeCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "17", want: CodeRateLimited, wantRetry: 17 * time.Second},
		{name: "rate limited seconds capped", status: http.StatusTooManyRequests, retryAfter: "7200", want: CodeRateLimited, wantRetry: time.Hour},
		{
			name: "rate limited date", status: http.StatusTooManyRequests,
			retryAfter: remoteProviderTestTime.Add(29 * time.Second).Format(http.TimeFormat),
			want:       CodeRateLimited, wantRetry: 29 * time.Second,
		},
		{
			name: "rate limited date capped", status: http.StatusTooManyRequests,
			retryAfter: remoteProviderTestTime.Add(2 * time.Hour).Format(http.TimeFormat),
			want:       CodeRateLimited, wantRetry: time.Hour,
		},
		{name: "server error", status: http.StatusBadGateway, body: upstreamSecret, want: CodeUnavailable},
		{name: "bad json", status: http.StatusOK, body: "{", want: CodeInvalidResponse},
		{name: "trailing json", status: http.StatusOK, body: `{"success":true,"result":[]} {}`, want: CodeInvalidResponse},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", responseBodyLimit+1), want: CodeInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerCloudflare, ZoneName: testZone,
				Credentials: map[string]string{"api_token": "cloudflare-secret-token"},
			}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.retryAfter != "" {
					w.Header().Set("Retry-After", test.retryAfter)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}), time.Second)
			_, err := adapter.PresentTXT(context.Background(), testChallenge())
			assertRemoteError(t, err, test.want)
			var remoteError *Error
			if !errors.As(err, &remoteError) || remoteError.RetryAfter != test.wantRetry {
				t.Fatalf("error = %+v, retry after want %s", err, test.wantRetry)
			}
			for _, sensitive := range []string{"cloudflare-secret-token", upstreamSecret, "Authorization"} {
				if strings.Contains(err.Error(), sensitive) || strings.Contains(fmt.Sprintf("%+v", err), sensitive) {
					t.Fatalf("error leaked %q: %+v", sensitive, err)
				}
			}
		})
	}
}

func TestSharedHTTP408TimeoutClassification(t *testing.T) {
	const upstreamSecret = "upstream-sensitive-408-response"
	for _, test := range []struct {
		name      string
		body      string
		want      ErrorCode
		temporary bool
		deadline  bool
	}{
		{
			name: "known credentials envelope",
			body: `{"success":false,"errors":[{"code":9109,"message":"` + upstreamSecret + `"}],"result":null}`,
			want: CodeCredentialsRejected,
		},
		{name: "empty body", want: CodeTimeout, temporary: true, deadline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{
				ProviderType: providerCloudflare, ZoneName: testZone,
				Credentials: map[string]string{"api_token": "cloudflare-secret-token"},
			}, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusRequestTimeout)
				_, _ = writer.Write([]byte(test.body))
			}), time.Second)
			_, err := adapter.PresentTXT(context.Background(), testChallenge())
			assertRemoteError(t, err, test.want)
			var remoteError *Error
			if !errors.As(err, &remoteError) || remoteError.Temporary != test.temporary ||
				errors.Is(err, context.DeadlineExceeded) != test.deadline {
				t.Fatalf("408 error = %+v", err)
			}
			for _, sensitive := range []string{"cloudflare-secret-token", upstreamSecret, "Authorization"} {
				if strings.Contains(err.Error(), sensitive) || strings.Contains(fmt.Sprintf("%+v", err), sensitive) {
					t.Fatalf("error leaked %q: %+v", sensitive, err)
				}
			}
		})
	}

	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound} {
		if err := classifyHTTP(httpResponse{status: status}, remoteProviderTestTime); err != nil {
			t.Fatalf("classifyHTTP(%d) error = %v", status, err)
		}
	}
}

func TestRedirectIsRejectedWithoutFollowing(t *testing.T) {
	var requests atomic.Int32
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "cloudflare-secret-token"},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "https://example.invalid/credential-capture")
		w.WriteHeader(http.StatusFound)
	}), time.Second)
	_, err := adapter.PresentTXT(context.Background(), testChallenge())
	assertRemoteError(t, err, CodeInvalidResponse)
	if requests.Load() != 1 {
		t.Fatalf("redirect request count = %d", requests.Load())
	}
}

func TestInternalRequestTimeout(t *testing.T) {
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "cloudflare-secret-token"},
	}, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}), 30*time.Millisecond)
	_, err := adapter.PresentTXT(context.Background(), testChallenge())
	assertRemoteError(t, err, CodeTimeout)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout does not match context deadline: %v", err)
	}
}

func TestBoundedHTTPRejectsNilContextWithoutPanicking(t *testing.T) {
	client := newBoundedHTTPClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("nil context must be rejected before transport")
		return nil, nil
	}), time.Second)
	_, err := client.do(nil, http.MethodGet, endpoint{
		baseURL: "https://api.example.test", host: "api.example.test",
	}, "/health", nil, nil)
	assertRemoteError(t, err, CodeInvalidInput)
}

func TestCallerCancellation(t *testing.T) {
	var requests atomic.Int32
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{
		ProviderType: providerCloudflare, ZoneName: testZone,
		Credentials: map[string]string{"api_token": "cloudflare-secret-token"},
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}), time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := adapter.PresentTXT(ctx, testChallenge())
	assertRemoteError(t, err, CodeCancelled)
	if !errors.Is(err, context.Canceled) || requests.Load() != 0 {
		t.Fatalf("cancellation error=%v requests=%d", err, requests.Load())
	}
}

func TestProductionClientUsesFixedHTTPSAndNoProxy(t *testing.T) {
	adapter := New(&staticSource{})
	transport, ok := adapter.http.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", adapter.http.client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("production transport must not use environment proxies")
	}
	want := map[string]string{
		"cloudflare": adapter.endpoints.cloudflare.baseURL,
		"aliyun":     adapter.endpoints.aliyun.baseURL,
		"dnspod":     adapter.endpoints.dnspod.baseURL,
		"dnscom":     adapter.endpoints.dnscom.baseURL,
		"dnsla":      adapter.endpoints.dnsla.baseURL,
	}
	for name, endpointURL := range want {
		if !strings.HasPrefix(endpointURL, "https://") {
			t.Errorf("%s endpoint is not HTTPS: %q", name, endpointURL)
		}
	}
	if adapter.endpoints.dnsla.baseURL != "https://api.dns.la" {
		t.Fatalf("DNS.LA endpoint = %q", adapter.endpoints.dnsla.baseURL)
	}
	if strings.Contains(fmt.Sprintf("%+v", adapter.endpoints), "dnsdun") {
		t.Fatal("production endpoints must not contain a dnsdun alias")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://api.cloudflare.com", nil)
	redirect, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	if !errors.Is(adapter.http.client.CheckRedirect(redirect, []*http.Request{request}), http.ErrUseLastResponse) {
		t.Fatal("redirect policy did not reject redirect")
	}
}

func assertRemoteError(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	if err == nil || ErrorCodeOf(err) != want || err.Error() != string(want) {
		t.Fatalf("error = %v (%q), want %q", err, ErrorCodeOf(err), want)
	}
}
