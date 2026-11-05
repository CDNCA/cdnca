package dnsacme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ClouDNS login test (https://www.cloudns.net/wiki/article/45/, read
// 2026-11-05): POST /login/login.json with sub-auth-id + auth-password answers
// HTTP 200 {"status":"Success"} or {"status":"Failed","statusDescription":
// "Invalid authentication, ..."}. Rate limiting is also a 200 "Failed"
// ("Request blocked. ... is sending more than ...").
const (
	clouDNSVerifyEndpoint  = "https://api.cloudns.net/login/login.json"
	clouDNSVerifyHost      = "api.cloudns.net"
	clouDNSVerifyBodySize  = 64 << 10
	clouDNSVerifyTimeout   = 5 * time.Second
	clouDNSVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

var clouDNSSubAuthIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

type ClouDNSProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
}

func NewClouDNSProviderVerifier() *ClouDNSProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newClouDNSProviderVerifier("", &http.Client{Transport: transport}, clouDNSVerifyTimeout)
}

func newClouDNSProviderVerifier(testEndpoint string, client *http.Client, timeout time.Duration) *ClouDNSProviderVerifier {
	if client == nil {
		client = &http.Client{}
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if timeout <= 0 {
		timeout = clouDNSVerifyTimeout
	}
	return &ClouDNSProviderVerifier{testEndpoint: testEndpoint, client: &configuredClient, timeout: timeout}
}

func (v *ClouDNSProviderVerifier) Verify(ctx context.Context, subAuthID, authPassword string) error {
	if !clouDNSSubAuthIDPattern.MatchString(subAuthID) || !validDNSComCredential(authPassword, 256, false) {
		return ErrProviderCredentialsInvalid
	}
	endpoint := clouDNSVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	form := url.Values{"sub-auth-id": {subAuthID}, "auth-password": {authPassword}}
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = clouDNSVerifyHost
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", clouDNSVerifyUserAgent)
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
	case response.StatusCode == http.StatusTooManyRequests:
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		return ErrProviderVerificationUnavailable
	case response.StatusCode != http.StatusOK:
		return ErrProviderVerificationInvalidResponse
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, clouDNSVerifyBodySize+1))
	if err != nil || len(body) > clouDNSVerifyBodySize {
		return ErrProviderVerificationInvalidResponse
	}
	var result struct {
		Status      *string `json:"status"`
		Description string  `json:"statusDescription"`
	}
	if json.Unmarshal(body, &result) != nil || result.Status == nil {
		return ErrProviderVerificationInvalidResponse
	}
	switch {
	case *result.Status == "Success":
		return nil
	case *result.Status != "Failed":
		return ErrProviderVerificationInvalidResponse
	case strings.HasPrefix(result.Description, "Invalid authentication"):
		return ErrProviderCredentialsRejected
	case strings.HasPrefix(result.Description, "Request blocked."):
		return &providerVerificationRetryError{}
	default:
		return ErrProviderVerificationInvalidResponse
	}
}

func exactClouDNSCredentials(credentials map[string]string) (string, string, error) {
	if len(credentials) != 2 {
		return "", "", ErrProviderCredentialsInvalid
	}
	subAuthID, idExists := credentials["sub_auth_id"]
	authPassword, passwordExists := credentials["auth_password"]
	if !idExists || !passwordExists || !clouDNSSubAuthIDPattern.MatchString(subAuthID) ||
		!validDNSComCredential(authPassword, 256, false) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return subAuthID, authPassword, nil
}
