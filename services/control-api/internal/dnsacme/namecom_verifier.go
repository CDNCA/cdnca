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

// name.com Core API: GET /core/v1/hello answers with the authenticated
// username (HelloResponse) and is the documented credentials check.
const (
	nameComVerifyEndpoint  = "https://api.name.com/core/v1/hello"
	nameComVerifyHost      = "api.name.com"
	nameComVerifyBodySize  = 64 << 10
	nameComVerifyTimeout   = 5 * time.Second
	nameComVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

type NameComProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
}

func NewNameComProviderVerifier() *NameComProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newNameComProviderVerifier("", &http.Client{Transport: transport}, nameComVerifyTimeout)
}

func newNameComProviderVerifier(testEndpoint string, client *http.Client, timeout time.Duration) *NameComProviderVerifier {
	if client == nil {
		client = &http.Client{}
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if timeout <= 0 {
		timeout = nameComVerifyTimeout
	}
	return &NameComProviderVerifier{testEndpoint: testEndpoint, client: &configuredClient, timeout: timeout}
}

func (v *NameComProviderVerifier) Verify(ctx context.Context, username, apiToken string) error {
	if !validNameComUsername(username) || !validNameComToken(apiToken) {
		return ErrProviderCredentialsInvalid
	}
	endpoint := nameComVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = nameComVerifyHost
	request.SetBasicAuth(username, apiToken)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", nameComVerifyUserAgent)

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
	body, err := io.ReadAll(io.LimitReader(response.Body, nameComVerifyBodySize+1))
	if err != nil || len(body) > nameComVerifyBodySize {
		return ErrProviderVerificationInvalidResponse
	}
	var hello struct {
		Username *string `json:"username"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if decoder.Decode(&hello) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || hello.Username == nil ||
		!strings.EqualFold(*hello.Username, username) {
		return ErrProviderVerificationInvalidResponse
	}
	return nil
}

func exactNameComCredentials(credentials map[string]string) (string, string, error) {
	if len(credentials) != 2 {
		return "", "", ErrProviderCredentialsInvalid
	}
	username, userExists := credentials["username"]
	apiToken, tokenExists := credentials["api_token"]
	if !userExists || !tokenExists || !validNameComUsername(username) || !validNameComToken(apiToken) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return username, apiToken, nil
}

// Printable ASCII without spaces; the Basic username cannot hold ':'.
func validNameComUsername(value string) bool {
	return validDNSComCredential(value, 128, false) && !strings.Contains(value, ":")
}

func validNameComToken(value string) bool {
	return validDNSComCredential(value, 256, false)
}
