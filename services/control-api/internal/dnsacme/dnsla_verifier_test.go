package dnsacme

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	dnslaTestAPIID     = "dnsla-api-id"
	dnslaTestAPISecret = "dnsla-api-secret"
	dnslaTestUpstream  = "sensitive upstream response"
)

func TestDNSLAProviderVerifierUsesReadOnlyDomainList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/api/domainList" || request.URL.RawQuery != "pageIndex=1&pageSize=1" {
			t.Errorf("request = %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		if request.Host != dnslaVerifyHost {
			t.Errorf("Host = %q", request.Host)
		}
		wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(dnslaTestAPIID+":"+dnslaTestAPISecret))
		if authorization := request.Header.Get("Authorization"); authorization != wantAuthorization {
			t.Errorf("Authorization does not match fixed Basic vector")
		}
		if request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") != dnslaVerifyUserAgent {
			t.Errorf("headers = %#v", request.Header)
		}
		_, _ = w.Write([]byte(`{"code":200,"msg":"","data":{"total":0,"results":[]}}`))
	}))
	t.Cleanup(server.Close)

	verifier := newDNSLAProviderVerifier(server.URL+"/api/domainList?pageIndex=1&pageSize=1", server.Client(), time.Second)
	if err := verifier.Verify(context.Background(), dnslaTestAPIID, dnslaTestAPISecret); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSLAProviderVerifierClassifiesResponses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: dnslaTestUpstream, want: ErrProviderCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: dnslaTestUpstream, want: ErrProviderCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "120", body: dnslaTestUpstream, want: ErrProviderVerificationRateLimited, wantRetry: "120"},
		{name: "rate limited date", status: http.StatusTooManyRequests, retryAfter: "Wed, 21 Oct 2015 07:28:00 GMT", body: dnslaTestUpstream, want: ErrProviderVerificationRateLimited, wantRetry: "Wed, 21 Oct 2015 07:28:00 GMT"},
		{name: "rate limited invalid retry", status: http.StatusTooManyRequests, retryAfter: dnslaTestUpstream, body: dnslaTestUpstream, want: ErrProviderVerificationRateLimited},
		{name: "http unavailable", status: http.StatusBadGateway, body: dnslaTestUpstream, want: ErrProviderVerificationUnavailable},
		{name: "redirect", status: http.StatusFound, body: dnslaTestUpstream, want: ErrProviderVerificationInvalidResponse},
		{name: "unexpected 4xx", status: http.StatusBadRequest, body: `{"code":200,"data":{"total":0,"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "provider bad request", status: http.StatusOK, body: `{"code":400,"msg":"sensitive upstream response","data":null}`, want: ErrProviderVerificationInvalidResponse},
		{name: "provider unavailable", status: http.StatusOK, body: `{"code":500,"msg":"sensitive upstream response","data":null}`, want: ErrProviderVerificationUnavailable},
		{name: "provider 6xx", status: http.StatusOK, body: `{"code":601,"msg":"sensitive upstream response","data":null}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string code", status: http.StatusOK, body: `{"code":"200","data":{"total":0,"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "bad json", status: http.StatusOK, body: `{`, want: ErrProviderVerificationInvalidResponse},
		{name: "trailing json", status: http.StatusOK, body: `{"code":200,"data":{"total":0,"results":[]}} {}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing code", status: http.StatusOK, body: `{"data":{"total":0,"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null code", status: http.StatusOK, body: `{"code":null,"data":{"total":0,"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing data", status: http.StatusOK, body: `{"code":200}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null data", status: http.StatusOK, body: `{"code":200,"data":null}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing total", status: http.StatusOK, body: `{"code":200,"data":{"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null total", status: http.StatusOK, body: `{"code":200,"data":{"total":null,"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string total", status: http.StatusOK, body: `{"code":200,"data":{"total":"0","results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "negative total", status: http.StatusOK, body: `{"code":200,"data":{"total":-1,"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing results", status: http.StatusOK, body: `{"code":200,"data":{"total":0}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null results", status: http.StatusOK, body: `{"code":200,"data":{"total":0,"results":null}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "invalid results", status: http.StatusOK, body: `{"code":200,"data":{"total":0,"results":{}}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string results", status: http.StatusOK, body: `{"code":200,"data":{"total":0,"results":"invalid"}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "zero total with domain", status: http.StatusOK, body: `{"code":200,"data":{"total":0,"results":[{}]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "positive total with empty first page", status: http.StatusOK, body: `{"code":200,"data":{"total":1,"results":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "first page longer than total", status: http.StatusOK, body: `{"code":200,"data":{"total":1,"results":[{},{}]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null domain element", status: http.StatusOK, body: `{"code":200,"data":{"total":1,"results":[null]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string domain element", status: http.StatusOK, body: `{"code":200,"data":{"total":1,"results":["sensitive upstream response"]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "number domain element", status: http.StatusOK, body: `{"code":200,"data":{"total":1,"results":[1]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "boolean domain element", status: http.StatusOK, body: `{"code":200,"data":{"total":1,"results":[true]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "array domain element", status: http.StatusOK, body: `{"code":200,"data":{"total":1,"results":[[]]}}`, want: ErrProviderVerificationInvalidResponse},
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
			err := newDNSLATestVerifier(server).Verify(context.Background(), dnslaTestAPIID, dnslaTestAPISecret)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retryAfter, test.wantRetry)
			}
			for _, sensitive := range []string{dnslaTestAPIID, dnslaTestAPISecret, dnslaTestUpstream} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
				}
			}
		})
	}
}

func TestDNSLAProviderVerifierAcceptsPartialFirstPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":2,"results":[{}]}}`))
	}))
	t.Cleanup(server.Close)

	if err := newDNSLATestVerifier(server).Verify(context.Background(), dnslaTestAPIID, dnslaTestAPISecret); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSLAProviderVerifierRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"results":[],"padding":"` + strings.Repeat("x", dnslaVerifyBodySize) + `"}}`))
	}))
	t.Cleanup(server.Close)
	err := newDNSLATestVerifier(server).Verify(context.Background(), dnslaTestAPIID, dnslaTestAPISecret)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSLAProviderVerifierTimeoutAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(server.Close)
	verifier := newDNSLAProviderVerifier(server.URL, server.Client(), 20*time.Millisecond)
	if err := verifier.Verify(context.Background(), dnslaTestAPIID, dnslaTestAPISecret); !errors.Is(err, ErrProviderVerificationTimeout) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.Verify(ctx, dnslaTestAPIID, dnslaTestAPISecret); err != context.Canceled {
		t.Fatalf("caller cancellation error = %v", err)
	}
}

func TestDNSLAProviderVerifierDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/followed" {
			followed.Add(1)
			_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"results":[]}}`))
			return
		}
		http.Redirect(w, request, "/followed", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	err := newDNSLATestVerifier(server).Verify(context.Background(), dnslaTestAPIID, dnslaTestAPISecret)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("redirect error = %v", err)
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was called %d times", followed.Load())
	}
}

func TestDNSLAProviderVerifierClassifiesNetworkFailureWithoutLeak(t *testing.T) {
	client := &http.Client{Transport: failingDNSLATransport{}}
	verifier := newDNSLAProviderVerifier("https://example.invalid", client, time.Second)
	err := verifier.Verify(context.Background(), dnslaTestAPIID, dnslaTestAPISecret)
	if !errors.Is(err, ErrProviderVerificationUnavailable) {
		t.Fatalf("Verify() error = %v", err)
	}
	for _, sensitive := range []string{dnslaTestAPIID, dnslaTestAPISecret, "sensitive transport detail"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
		}
	}
}

func TestDNSLAProviderVerifierRejectsInvalidCredentialsBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)
	verifier := newDNSLATestVerifier(server)
	for _, credentials := range [][2]string{
		{"", dnslaTestAPISecret},
		{dnslaTestAPIID, ""},
		{"api:id", dnslaTestAPISecret},
		{dnslaTestAPIID, "secret\nvalue"},
		{strings.Repeat("a", 4097), dnslaTestAPISecret},
	} {
		if err := verifier.Verify(context.Background(), credentials[0], credentials[1]); !errors.Is(err, ErrProviderCredentialsInvalid) {
			t.Fatalf("Verify(redacted) error = %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid credentials made %d network calls", calls.Load())
	}
}

func TestDNSLAProductionVerifierUsesFixedHTTPSDomainListEndpoint(t *testing.T) {
	verifier := NewDNSLAProviderVerifier()
	if verifier.testEndpoint != "" || verifier.timeout != 5*time.Second {
		t.Fatalf("production verifier = %#v", verifier)
	}
	if dnslaVerifyEndpoint != "https://api.dns.la/api/domainList?pageIndex=1&pageSize=1" {
		t.Fatalf("production endpoint = %q", dnslaVerifyEndpoint)
	}
	transport, ok := verifier.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("production transport = %#v; proxy must be disabled", verifier.client.Transport)
	}
}

func newDNSLATestVerifier(server *httptest.Server) *DNSLAProviderVerifier {
	return newDNSLAProviderVerifier(server.URL+"/api/domainList?pageIndex=1&pageSize=1", server.Client(), time.Second)
}

type failingDNSLATransport struct{}

func (failingDNSLATransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("sensitive transport detail")
}
