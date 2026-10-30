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
	dnscomTestAPIKey    = "c7722149110b7492a2e5cf1d8f3f966b"
	dnscomTestAPISecret = "ecb4ff0e877a83292b9f35067e9ae673"
	dnscomTestUpstream  = "sensitive upstream response"
)

func TestDNSComSignerMatchesDocumentedAlgorithmNotConflictingPrintedDigest(t *testing.T) {
	parameters := map[string]string{
		"timestamp": "1521005892",
		"api_key":   dnscomTestAPIKey,
		"domain":    "dns.com",
	}
	wantCanonical := "api_key=c7722149110b7492a2e5cf1d8f3f966b&domain=dns.com&timestamp=1521005892"
	if canonical := canonicalDNSComParameters(parameters); canonical != wantCanonical {
		t.Fatalf("canonical parameters = %q, want %q", canonical, wantCanonical)
	}
	if signature := signDNSComRequest(parameters, dnscomTestAPISecret); signature != "54fe71ca13c97703fadeed7aacc80a15" {
		t.Fatalf("signature = %q", signature)
	} else if signature == "0eb4933a634000ce215370683d6f1338" {
		t.Fatal("signature unexpectedly matched the official page's irreproducible printed digest")
	}
}

func TestDNSComProviderVerifierSignsReadOnlyDomainList(t *testing.T) {
	const expectedQuery = "api_key=c7722149110b7492a2e5cf1d8f3f966b&page=1&paginate=1&" +
		"sign=4dbb505ac7a20913a33736daac5ef216&timestamp=1521005892"
	fixedTime := time.Unix(1521005892, 987654321)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/domain/lists/" || r.URL.RawQuery != expectedQuery {
			t.Errorf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if r.Host != dnscomVerifyHost {
			t.Errorf("Host = %q", r.Host)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != dnscomVerifyUserAgent {
			t.Errorf("User-Agent = %q", got)
		}
		_, _ = w.Write([]byte(`{"code":0,"message":"","data":{"total":0,"data":[]}}`))
	}))
	t.Cleanup(server.Close)

	verifier := newDNSComProviderVerifier(
		server.URL+"/api/domain/lists/",
		server.Client(),
		time.Second,
		func() time.Time { return fixedTime },
	)
	if err := verifier.Verify(context.Background(), dnscomTestAPIKey, dnscomTestAPISecret); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSComProviderVerifierClassifiesResponses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       error
		wantRetry  string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: dnscomTestUpstream, want: ErrProviderCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: dnscomTestUpstream, want: ErrProviderCredentialsRejected},
		{name: "documented generic failure", status: http.StatusOK, body: `{"code":1,"message":"sensitive upstream response","data":[]}`, want: ErrProviderVerificationInvalidResponse},
		{name: "rate limited", status: http.StatusTooManyRequests, retryAfter: "120", body: dnscomTestUpstream, want: ErrProviderVerificationRateLimited, wantRetry: "120"},
		{name: "rate limited date", status: http.StatusTooManyRequests, retryAfter: "Wed, 21 Oct 2015 07:28:00 GMT", body: dnscomTestUpstream, want: ErrProviderVerificationRateLimited, wantRetry: "Wed, 21 Oct 2015 07:28:00 GMT"},
		{name: "rate limited invalid retry", status: http.StatusTooManyRequests, retryAfter: dnscomTestUpstream, want: ErrProviderVerificationRateLimited},
		{name: "unavailable", status: http.StatusBadGateway, body: dnscomTestUpstream, want: ErrProviderVerificationUnavailable},
		{name: "redirect", status: http.StatusFound, body: dnscomTestUpstream, want: ErrProviderVerificationInvalidResponse},
		{name: "unexpected http status", status: http.StatusTeapot, body: `{"code":0,"data":{"total":0,"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "unknown provider code", status: http.StatusOK, body: `{"code":405,"message":"sensitive upstream response","data":[]}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string code", status: http.StatusOK, body: `{"code":"0","data":{"total":0,"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "bad json", status: http.StatusOK, body: `{`, want: ErrProviderVerificationInvalidResponse},
		{name: "trailing json", status: http.StatusOK, body: `{"code":0,"data":{"total":0,"data":[]}} {}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing code", status: http.StatusOK, body: `{"data":{"total":0,"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null code", status: http.StatusOK, body: `{"code":null,"data":{"total":0,"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing data", status: http.StatusOK, body: `{"code":0}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null data", status: http.StatusOK, body: `{"code":0,"data":null}`, want: ErrProviderVerificationInvalidResponse},
		{name: "invalid data", status: http.StatusOK, body: `{"code":0,"data":[]}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing total", status: http.StatusOK, body: `{"code":0,"data":{"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null total", status: http.StatusOK, body: `{"code":0,"data":{"total":null,"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string total", status: http.StatusOK, body: `{"code":0,"data":{"total":"0","data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "negative total", status: http.StatusOK, body: `{"code":0,"data":{"total":-1,"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "missing domains", status: http.StatusOK, body: `{"code":0,"data":{"total":0}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null domains", status: http.StatusOK, body: `{"code":0,"data":{"total":0,"data":null}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "invalid domains", status: http.StatusOK, body: `{"code":0,"data":{"total":0,"data":{}}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string domains", status: http.StatusOK, body: `{"code":0,"data":{"total":0,"data":"invalid"}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "zero total with domain", status: http.StatusOK, body: `{"code":0,"data":{"total":0,"data":[{}]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "positive total with empty first page", status: http.StatusOK, body: `{"code":0,"data":{"total":1,"data":[]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "first page longer than total", status: http.StatusOK, body: `{"code":0,"data":{"total":1,"data":[{},{}]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "null domain element", status: http.StatusOK, body: `{"code":0,"data":{"total":1,"data":[null]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "string domain element", status: http.StatusOK, body: `{"code":0,"data":{"total":1,"data":["sensitive upstream response"]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "number domain element", status: http.StatusOK, body: `{"code":0,"data":{"total":1,"data":[1]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "boolean domain element", status: http.StatusOK, body: `{"code":0,"data":{"total":1,"data":[true]}}`, want: ErrProviderVerificationInvalidResponse},
		{name: "array domain element", status: http.StatusOK, body: `{"code":0,"data":{"total":1,"data":[[]]}}`, want: ErrProviderVerificationInvalidResponse},
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
			err := newDNSComTestVerifier(server).Verify(context.Background(), dnscomTestAPIKey, dnscomTestAPISecret)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if retryAfter := ProviderVerificationRetryAfter(err); retryAfter != test.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", retryAfter, test.wantRetry)
			}
			for _, sensitive := range []string{
				dnscomTestAPIKey,
				dnscomTestAPISecret,
				dnscomTestUpstream,
				"api_secret",
				"api_key=" + dnscomTestAPIKey,
			} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
				}
			}
		})
	}
}

func TestDNSComProviderVerifierAcceptsPartialFirstPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"total":2,"data":[{}]}}`))
	}))
	t.Cleanup(server.Close)

	if err := newDNSComTestVerifier(server).Verify(context.Background(), dnscomTestAPIKey, dnscomTestAPISecret); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSComProviderVerifierRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"total":0,"data":[],"padding":"` +
			strings.Repeat("x", dnscomVerifyBodySize) + `"}}`))
	}))
	t.Cleanup(server.Close)
	err := newDNSComTestVerifier(server).Verify(context.Background(), dnscomTestAPIKey, dnscomTestAPISecret)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestDNSComProviderVerifierTimeoutAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(server.Close)
	verifier := newDNSComProviderVerifier(server.URL, server.Client(), 20*time.Millisecond, time.Now)
	if err := verifier.Verify(context.Background(), dnscomTestAPIKey, dnscomTestAPISecret); !errors.Is(err, ErrProviderVerificationTimeout) {
		t.Fatalf("timeout error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.Verify(ctx, dnscomTestAPIKey, dnscomTestAPISecret); err != context.Canceled {
		t.Fatalf("caller cancellation error = %v", err)
	}
}

func TestDNSComProviderVerifierDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/followed" {
			followed.Add(1)
			_, _ = w.Write([]byte(`{"code":0,"data":{"total":0,"data":[]}}`))
			return
		}
		http.Redirect(w, r, "/followed", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	err := newDNSComTestVerifier(server).Verify(context.Background(), dnscomTestAPIKey, dnscomTestAPISecret)
	if !errors.Is(err, ErrProviderVerificationInvalidResponse) {
		t.Fatalf("redirect error = %v", err)
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was called %d times", followed.Load())
	}
}

func TestDNSComProviderVerifierClassifiesNetworkFailureWithoutLeak(t *testing.T) {
	client := &http.Client{Transport: failingDNSComTransport{}}
	verifier := newDNSComProviderVerifier("https://example.invalid", client, time.Second, time.Now)
	err := verifier.Verify(context.Background(), dnscomTestAPIKey, dnscomTestAPISecret)
	if !errors.Is(err, ErrProviderVerificationUnavailable) {
		t.Fatalf("Verify() error = %v", err)
	}
	for _, sensitive := range []string{dnscomTestAPIKey, dnscomTestAPISecret, "sensitive transport detail"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("error leaked sensitive value %q: %q", sensitive, err)
		}
	}
}

func TestDNSComProductionVerifierUsesFixedHTTPSDomainListEndpoint(t *testing.T) {
	verifier := NewDNSComProviderVerifier()
	if verifier.testEndpoint != "" {
		t.Fatalf("production testEndpoint = %q", verifier.testEndpoint)
	}
	if verifier.timeout != 5*time.Second {
		t.Fatalf("production timeout = %s", verifier.timeout)
	}
	if dnscomVerifyEndpoint != "https://openapi.dns.com/api/domain/lists/" {
		t.Fatalf("production endpoint = %q", dnscomVerifyEndpoint)
	}
	transport, ok := verifier.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("production transport = %#v; proxy must be disabled", verifier.client.Transport)
	}
}

func TestDNSComProviderVerifierRejectsInvalidCredentialsBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)
	verifier := newDNSComTestVerifier(server)
	for _, credentials := range [][2]string{
		{"", dnscomTestAPISecret},
		{dnscomTestAPIKey, ""},
		{"key&other=value", dnscomTestAPISecret},
		{dnscomTestAPIKey, "secret\nvalue"},
	} {
		if err := verifier.Verify(context.Background(), credentials[0], credentials[1]); !errors.Is(err, ErrProviderCredentialsInvalid) {
			t.Fatalf("Verify(%q, redacted) error = %v", credentials[0], err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid credentials made %d network calls", calls.Load())
	}
}

func newDNSComTestVerifier(server *httptest.Server) *DNSComProviderVerifier {
	return newDNSComProviderVerifier(
		server.URL+"/api/domain/lists/",
		server.Client(),
		time.Second,
		func() time.Time { return time.Unix(1521005892, 0) },
	)
}

type failingDNSComTransport struct{}

func (failingDNSComTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("sensitive transport detail")
}
