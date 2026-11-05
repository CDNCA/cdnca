package dnsacme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Namesilo API (https://www.namesilo.com/api-reference, read 2026-11-05):
// GET /api/listDomains?version=1&type=json&key=<key> answers reply.code 300
// on success; 110 invalid API key, 111 invalid user, 112 sub-accounts have
// no API, 113 "cannot be accessed from your IP", 120 key not passed by GET;
// 400 "still processing - request will need to be re-submitted". The key is
// in the query (the only documented form); errors never carry the URL.
const (
	namesiloVerifyEndpoint = "https://www.namesilo.com/api/listDomains"
	namesiloVerifyHost     = "www.namesilo.com"
	namesiloVerifyBodySize = 256 << 10
	namesiloVerifyTimeout  = 5 * time.Second
)

type NamesiloProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
}

func NewNamesiloProviderVerifier() *NamesiloProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newNamesiloProviderVerifier("", &http.Client{Transport: transport}, namesiloVerifyTimeout)
}

func newNamesiloProviderVerifier(testEndpoint string, client *http.Client, timeout time.Duration) *NamesiloProviderVerifier {
	if client == nil {
		client = &http.Client{}
	}
	configured := *client
	configured.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if timeout <= 0 {
		timeout = namesiloVerifyTimeout
	}
	return &NamesiloProviderVerifier{testEndpoint: testEndpoint, client: &configured, timeout: timeout}
}

func (v *NamesiloProviderVerifier) Verify(ctx context.Context, apiKey string) error {
	if !validDNSComCredential(apiKey, 128, false) {
		return ErrProviderCredentialsInvalid
	}
	endpoint := namesiloVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}
	query := url.Values{"version": {"1"}, "type": {"json"}, "key": {apiKey}, "pageSize": {"1"}}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = namesiloVerifyHost
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", providerVerifyUserAgent)
	response, err := v.client.Do(request)
	if err != nil {
		// err is a *url.Error holding the URL (and the key): never returned.
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
	case response.StatusCode == http.StatusTooManyRequests:
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		return ErrProviderVerificationUnavailable
	case response.StatusCode != http.StatusOK:
		return ErrProviderVerificationInvalidResponse
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, namesiloVerifyBodySize+1))
	if err != nil || len(body) > namesiloVerifyBodySize {
		return ErrProviderVerificationInvalidResponse
	}
	var envelope struct {
		Reply *struct {
			Code json.RawMessage `json:"code"`
		} `json:"reply"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if decoder.Decode(&envelope) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || envelope.Reply == nil {
		return ErrProviderVerificationInvalidResponse
	}
	// The JSON is converted from XML: the code may be a number or a string.
	switch strings.Trim(string(envelope.Reply.Code), `"`) {
	case "300":
		return nil
	case "109", "110", "111", "112", "113", "120":
		return ErrProviderCredentialsRejected
	case "400":
		return &providerVerificationRetryError{}
	case "115", "201":
		return ErrProviderVerificationUnavailable
	default:
		return ErrProviderVerificationInvalidResponse
	}
}

func exactNamesiloCredentials(credentials map[string]string) (string, error) {
	apiKey, err := exactCredential(credentials, "key")
	if err != nil || !validDNSComCredential(apiKey, 128, false) {
		return "", ErrProviderCredentialsInvalid
	}
	return apiKey, nil
}
