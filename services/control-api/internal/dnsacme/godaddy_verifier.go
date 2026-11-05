package dnsacme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// GoDaddy Domains v1 (https://developer.godaddy.com/openapi/domains-v1.json,
// read 2026-11-05): GET /v1/domains?limit=1 with "Authorization: sso-key
// KEY:SECRET" answers a JSON array of the account's domains; 401 is a bad
// key, 403 a key whose account may not use the API (the auth guide: "A valid
// credential on an ineligible account is still refused with a 403"), 429
// ErrorLimit with Retry-After.
const (
	goDaddyVerifyEndpoint = "https://api.godaddy.com/v1/domains?limit=1"
	goDaddyVerifyHost     = "api.godaddy.com"
	goDaddyVerifyBodySize = 64 << 10
	goDaddyVerifyTimeout  = 5 * time.Second
	// providerVerifyUserAgent is the verifiers' shared User-Agent value.
	providerVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

type GoDaddyProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
}

func NewGoDaddyProviderVerifier() *GoDaddyProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newGoDaddyProviderVerifier("", &http.Client{Transport: transport}, goDaddyVerifyTimeout)
}

func newGoDaddyProviderVerifier(testEndpoint string, client *http.Client, timeout time.Duration) *GoDaddyProviderVerifier {
	if client == nil {
		client = &http.Client{}
	}
	configured := *client
	configured.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if timeout <= 0 {
		timeout = goDaddyVerifyTimeout
	}
	return &GoDaddyProviderVerifier{testEndpoint: testEndpoint, client: &configured, timeout: timeout}
}

func (v *GoDaddyProviderVerifier) Verify(ctx context.Context, apiKey, apiSecret string) error {
	if !validGoDaddyKey(apiKey) || !validDNSComCredential(apiSecret, 256, false) {
		return ErrProviderCredentialsInvalid
	}
	endpoint := goDaddyVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = goDaddyVerifyHost
	request.Header.Set("Authorization", "sso-key "+apiKey+":"+apiSecret)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", providerVerifyUserAgent)
	response, err := v.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return ErrProviderVerificationTimeout
		}
		return ErrProviderVerificationUnavailable
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return ErrProviderCredentialsRejected
	case response.StatusCode == http.StatusTooManyRequests:
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		return ErrProviderVerificationUnavailable
	case response.StatusCode != http.StatusOK:
		return ErrProviderVerificationInvalidResponse
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, goDaddyVerifyBodySize+1))
	if err != nil || len(body) > goDaddyVerifyBodySize {
		return ErrProviderVerificationInvalidResponse
	}
	var domains []json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if decoder.Decode(&domains) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || domains == nil {
		return ErrProviderVerificationInvalidResponse
	}
	return nil
}

func exactGoDaddyCredentials(credentials map[string]string) (string, string, error) {
	if len(credentials) != 2 {
		return "", "", ErrProviderCredentialsInvalid
	}
	apiKey, keyExists := credentials["api_key"]
	apiSecret, secretExists := credentials["api_secret"]
	if !keyExists || !secretExists || !validGoDaddyKey(apiKey) || !validDNSComCredential(apiSecret, 256, false) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return apiKey, apiSecret, nil
}

// Printable ASCII without spaces; "sso-key KEY:SECRET" splits at the first ':'.
func validGoDaddyKey(value string) bool {
	return validDNSComCredential(value, 128, false) && !strings.Contains(value, ":")
}
