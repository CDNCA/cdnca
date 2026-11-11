package challenge

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Turnstile / reCAPTCHA v3 answers fall into passed, refused
// (ErrExternalVerification, 403) and unavailable (ErrExternalUnavailable, 503).
func TestSiteVerifyProvidersClassifyPassRefuseUnavailable(t *testing.T) {
	fresh := time.Now().UTC().Format(time.RFC3339)
	stale := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	tests := []struct {
		name     string
		provider ExternalProvider
		status   int
		body     string
		want     error
	}{
		{"turnstile ok", ProviderTurnstile, 200, `{"success":true,"hostname":"www.example.com","action":"cdnca_challenge"}`, nil},
		{"turnstile refused", ProviderTurnstile, 200, `{"success":false,"error-codes":["invalid-input-response"]}`, ErrExternalVerification},
		{"turnstile duplicate", ProviderTurnstile, 200, `{"success":false,"error-codes":["timeout-or-duplicate"]}`, ErrExternalVerification},
		{"turnstile other host", ProviderTurnstile, 200, `{"success":true,"hostname":"evil.example","action":"cdnca_challenge"}`, ErrExternalVerification},
		{"turnstile other action", ProviderTurnstile, 200, `{"success":true,"hostname":"www.example.com","action":"login"}`, ErrExternalVerification},
		{"turnstile bad secret", ProviderTurnstile, 200, `{"success":false,"error-codes":["invalid-input-secret"]}`, ErrExternalUnavailable},
		{"turnstile internal", ProviderTurnstile, 200, `{"success":false,"error-codes":["internal-error"]}`, ErrExternalUnavailable},
		{"turnstile 500", ProviderTurnstile, 500, `{}`, ErrExternalUnavailable},
		{"turnstile not json", ProviderTurnstile, 200, `<html>`, ErrExternalUnavailable},
		{"recaptcha ok", ProviderRecaptchaV3, 200, `{"success":true,"hostname":"www.example.com","action":"cdnca_challenge","score":0.7,"challenge_ts":"` + fresh + `"}`, nil},
		{"recaptcha low score", ProviderRecaptchaV3, 200, `{"success":true,"hostname":"www.example.com","action":"cdnca_challenge","score":0.3,"challenge_ts":"` + fresh + `"}`, ErrExternalVerification},
		{"recaptcha stale", ProviderRecaptchaV3, 200, `{"success":true,"hostname":"www.example.com","action":"cdnca_challenge","score":0.9,"challenge_ts":"` + stale + `"}`, ErrExternalVerification},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := externalRoundTripper(func(request *http.Request) (*http.Response, error) {
				want := turnstileVerifyURL
				if test.provider == ProviderRecaptchaV3 {
					want = recaptchaVerifyURL
				}
				if request.URL.String() != want {
					t.Fatalf("provider URL = %s", request.URL)
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})
			verifier, err := NewHTTPExternalVerifier(&http.Client{Transport: transport}, ExternalCredential{
				Provider: test.provider, AppID: "6Le_site-key", Secret: []byte("provider-secret-0123456789abcdef"),
				Environment: ExternalProduction,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := validExternalRequest(test.provider)
			request.AppID, request.Proof, request.Host = "6Le_site-key", "token-1", "www.example.com"
			_, err = VerifyExternal(context.Background(), request, verifier)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("VerifyExternal() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHostMatchesWildcardOnlyBelowTheDomain(t *testing.T) {
	for _, test := range []struct {
		policy, token string
		want          bool
	}{
		{"www.example.com", "www.example.com", true}, {"www.example.com", "WWW.example.com", true},
		{"www.example.com", "example.com", false}, {"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false}, {"*.example.com", "aexample.com", false},
	} {
		if got := hostMatches(test.policy, test.token); got != test.want {
			t.Errorf("hostMatches(%q, %q) = %v", test.policy, test.token, got)
		}
	}
}

func TestExternalBreakerOpensAfterFiveUnavailableAndProbes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	breaker := &externalBreaker{state: map[ExternalProvider]breakerState{}, now: func() time.Time { return now }}
	for range breakerThreshold {
		if !breaker.allow(ProviderTurnstile) {
			t.Fatal("breaker opened early")
		}
		breaker.record(ProviderTurnstile, true)
	}
	if breaker.allow(ProviderTurnstile) || !breaker.allow(ProviderRecaptchaV3) {
		t.Fatal("breaker must be open for the failing provider only")
	}
	now = now.Add(breakerOpenFor)
	if !breaker.allow(ProviderTurnstile) || breaker.allow(ProviderTurnstile) {
		t.Fatal("after the open window exactly one probe passes")
	}
	breaker.record(ProviderTurnstile, false)
	if !breaker.allow(ProviderTurnstile) {
		t.Fatal("a passed probe closes the breaker")
	}
}
