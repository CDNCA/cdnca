package dnsacme

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Namecheap XML API credential check (read 2026-11-05: global parameters,
// domains.getList): POST /xml.response Command=namecheap.domains.getList
// PageSize=10. Status="OK" accepts; error numbers 1010000-1019999 (APIUser /
// APIKey / ClientIp missing, invalid or locked, including a ClientIp missing
// from the account whitelist) reject. ClientIp is IPv4 only.
const (
	namecheapVerifyEndpoint  = "https://api.namecheap.com/xml.response"
	namecheapVerifyHost      = "api.namecheap.com"
	namecheapVerifyBodySize  = 256 << 10
	namecheapVerifyTimeout   = 5 * time.Second
	namecheapVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

type NamecheapProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
}

func NewNamecheapProviderVerifier() *NamecheapProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newNamecheapProviderVerifier("", &http.Client{Transport: transport}, namecheapVerifyTimeout)
}

func newNamecheapProviderVerifier(testEndpoint string, client *http.Client, timeout time.Duration) *NamecheapProviderVerifier {
	if client == nil {
		client = &http.Client{}
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if timeout <= 0 {
		timeout = namecheapVerifyTimeout
	}
	return &NamecheapProviderVerifier{testEndpoint: testEndpoint, client: &configuredClient, timeout: timeout}
}

func (v *NamecheapProviderVerifier) Verify(ctx context.Context, username, apiKey, sourceIP string) error {
	if !validDNSComCredential(username, 64, false) || !validDNSComCredential(apiKey, 128, false) || !validNamecheapSourceIP(sourceIP) {
		return ErrProviderCredentialsInvalid
	}
	endpoint := namecheapVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	form := url.Values{"ApiUser": {username}, "ApiKey": {apiKey}, "UserName": {username}, "ClientIp": {sourceIP},
		"Command": {"namecheap.domains.getList"}, "PageSize": {"10"}}
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = namecheapVerifyHost
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/xml")
	request.Header.Set("User-Agent", namecheapVerifyUserAgent)
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
	body, err := io.ReadAll(io.LimitReader(response.Body, namecheapVerifyBodySize+1))
	if err != nil || len(body) > namecheapVerifyBodySize {
		return ErrProviderVerificationInvalidResponse
	}
	var result struct {
		XMLName xml.Name `xml:"ApiResponse"`
		Status  string   `xml:"Status,attr"`
		Errors  []struct {
			Number string `xml:"Number,attr"`
		} `xml:"Errors>Error"`
	}
	if xml.Unmarshal(body, &result) != nil {
		return ErrProviderVerificationInvalidResponse
	}
	if result.Status == "OK" && len(result.Errors) == 0 {
		return nil
	}
	if result.Status != "ERROR" || len(result.Errors) == 0 {
		return ErrProviderVerificationInvalidResponse
	}
	if code, err := strconv.Atoi(result.Errors[0].Number); err == nil && code >= 1010000 && code <= 1019999 {
		return ErrProviderCredentialsRejected
	}
	return ErrProviderVerificationInvalidResponse
}

func validNamecheapSourceIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func exactNamecheapCredentials(credentials map[string]string) (string, string, string, error) {
	if len(credentials) != 3 {
		return "", "", "", ErrProviderCredentialsInvalid
	}
	username, userExists := credentials["username"]
	apiKey, keyExists := credentials["api_key"]
	sourceIP, ipExists := credentials["source_ip"]
	if !userExists || !keyExists || !ipExists || !validDNSComCredential(username, 64, false) ||
		!validDNSComCredential(apiKey, 128, false) || !validNamecheapSourceIP(sourceIP) {
		return "", "", "", ErrProviderCredentialsInvalid
	}
	return username, apiKey, sourceIP, nil
}
