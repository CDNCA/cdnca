package challenge

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type externalRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip externalRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestHTTPExternalVerifierUsesProviderContractsAndKeepsSecretsServerSide(t *testing.T) {
	tests := []struct {
		provider ExternalProvider
		proof    string
		body     string
		path     string
	}{
		{ProviderTencent, `{"ticket":"ticket-1","randstr":"rand-1"}`, `{"response":1,"evil_level":0}`, "/ticket/verify"},
		{ProviderGeetestV4, `{"lot_number":"lot-1","captcha_output":"output-1","pass_token":"pass-1","gen_time":"1700000000"}`, `{"result":"success","reason":""}`, "/validate"},
	}
	for _, test := range tests {
		t.Run(string(test.provider), func(t *testing.T) {
			transport := externalRoundTripper(func(request *http.Request) (*http.Response, error) {
				if request.URL.Scheme != "https" || request.URL.Path != test.path {
					t.Fatalf("provider URL = %s", request.URL)
				}
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(body), `"secret"`) || strings.Contains(request.URL.RawQuery, "secret") {
					t.Fatalf("credential key name leaked into request: %s %s", request.URL.RawQuery, body)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})
			verifier, err := NewHTTPExternalVerifier(&http.Client{Transport: transport}, ExternalCredential{
				Provider: test.provider, AppID: "app-123", Secret: []byte("provider-secret-0123456789abcdef"), Environment: ExternalProduction,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := validExternalRequest(test.provider)
			request.Proof = test.proof
			result, err := VerifyExternal(context.Background(), request, verifier)
			if err != nil || !result.Valid || result.AppID != request.AppID || result.ReplayKey == "" {
				t.Fatalf("VerifyExternal() = (%+v, %v)", result, err)
			}
		})
	}
}

func TestExternalVerificationServiceFailsClosedOnReplayCapacityAndTimeout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	service, err := NewExternalVerificationService(
		&verifierStub{result: ExternalResult{Valid: true, AppID: "app-123", ReplayKey: "once"}},
		NewMemoryExternalReplayStore(1), 1, time.Minute, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	request := validExternalRequest(ProviderTencent)
	if _, err := service.Verify(context.Background(), request); err != nil {
		t.Fatalf("first Verify() error = %v", err)
	}
	if _, err := service.Verify(context.Background(), request); err == nil {
		t.Fatal("replayed proof accepted")
	}
	request.SiteID = "site-b"
	if _, err := service.Verify(context.Background(), request); err == nil {
		t.Fatal("full replay store silently evicted a live one-time fact")
	}
}

func TestRotatingExternalVerifierRejectsBadCandidateAndKeepsLKG(t *testing.T) {
	transport := externalRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"response":1,"evil_level":0}`))}, nil
	})
	credentials := []ExternalCredential{{Provider: ProviderTencent, AppID: "app-123",
		Secret: []byte("provider-secret-0123456789abcdef"), Environment: ExternalProduction}}
	verifier, err := NewRotatingExternalVerifier(&http.Client{Transport: transport}, 7, credentials)
	if err != nil {
		t.Fatal(err)
	}
	bad := []ExternalCredential{{Provider: ProviderTencent, AppID: "app-123", Secret: []byte("short"), Environment: ExternalProduction}}
	if err := verifier.Activate(8, bad); err == nil {
		t.Fatal("bad credential candidate activated")
	}
	request := validExternalRequest(ProviderTencent)
	request.Proof = `{"ticket":"ticket-1","randstr":"rand-1"}`
	if _, err := VerifyExternal(context.Background(), request, verifier); err != nil {
		t.Fatalf("last-known-good credential stopped working: %v", err)
	}
}

func TestHTTPExternalVerifierFailsClosedOnTimeoutAndUnknownProofField(t *testing.T) {
	calls := 0
	transport := externalRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, context.DeadlineExceeded
	})
	verifier, err := NewHTTPExternalVerifier(&http.Client{Transport: transport}, ExternalCredential{
		Provider: ProviderTencent, AppID: "app-123", Secret: []byte("provider-secret-0123456789abcdef"), Environment: ExternalSandbox,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := validExternalRequest(ProviderTencent)
	request.Proof = `{"ticket":"ticket-1","randstr":"rand-1","extra":"blocked"}`
	if _, err := VerifyExternal(context.Background(), request, verifier); err == nil || calls != 0 {
		t.Fatalf("unknown proof field reached provider: err=%v calls=%d", err, calls)
	}
	request.Proof = `{"ticket":"ticket-1","randstr":"rand-1"}`
	if _, err := VerifyExternal(context.Background(), request, verifier); err == nil || calls != 1 {
		t.Fatalf("provider timeout accepted: err=%v calls=%d", err, calls)
	}
}
