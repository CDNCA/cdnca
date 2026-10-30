package dnsacme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	dnslaVerifyEndpoint  = "https://api.dns.la/api/domainList?pageIndex=1&pageSize=1"
	dnslaVerifyHost      = "api.dns.la"
	dnslaVerifyBodySize  = 64 << 10
	dnslaVerifyTimeout   = 5 * time.Second
	dnslaVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

type DNSLAProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
}

func NewDNSLAProviderVerifier() *DNSLAProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newDNSLAProviderVerifier("", &http.Client{Transport: transport}, dnslaVerifyTimeout)
}

func newDNSLAProviderVerifier(testEndpoint string, client *http.Client, timeout time.Duration) *DNSLAProviderVerifier {
	if client == nil {
		client = &http.Client{}
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if timeout <= 0 {
		timeout = dnslaVerifyTimeout
	}
	return &DNSLAProviderVerifier{testEndpoint: testEndpoint, client: &configuredClient, timeout: timeout}
}

func (v *DNSLAProviderVerifier) Verify(ctx context.Context, apiID, apiSecret string) error {
	if !validDNSLAUser(apiID) || !validDNSLAPassword(apiSecret) {
		return ErrProviderCredentialsInvalid
	}
	endpoint := dnslaVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = dnslaVerifyHost
	request.SetBasicAuth(apiID, apiSecret)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", dnslaVerifyUserAgent)

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

	body, bodyErr := io.ReadAll(io.LimitReader(response.Body, dnslaVerifyBodySize+1))
	var envelope struct {
		Code *int            `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	decoded := false
	if bodyErr == nil && len(body) <= dnslaVerifyBodySize {
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		if err := decoder.Decode(&envelope); err == nil {
			decoded = errors.Is(decoder.Decode(&struct{}{}), io.EOF) && envelope.Code != nil
		}
	}
	if decoded && *envelope.Code == http.StatusTooManyRequests {
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
	}
	if decoded && *envelope.Code >= 500 && *envelope.Code <= 599 {
		return ErrProviderVerificationUnavailable
	}
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
	if !decoded {
		return ErrProviderVerificationInvalidResponse
	}
	if *envelope.Code != http.StatusOK || !validDNSLADomainList(envelope.Data) {
		return ErrProviderVerificationInvalidResponse
	}
	return nil
}

func validDNSLADomainList(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var data struct {
		Total   *int64          `json:"total"`
		Results json.RawMessage `json:"results"`
	}
	if json.Unmarshal(raw, &data) != nil || data.Total == nil || *data.Total < 0 || len(data.Results) == 0 {
		return false
	}
	var results []json.RawMessage
	if json.Unmarshal(data.Results, &results) != nil || results == nil || int64(len(results)) > *data.Total {
		return false
	}
	if (*data.Total == 0) != (len(results) == 0) {
		return false
	}
	for _, result := range results {
		var object map[string]json.RawMessage
		if json.Unmarshal(result, &object) != nil || object == nil {
			return false
		}
	}
	return true
}

func validDNSLAUser(value string) bool {
	return validDNSLACredential(value) && !strings.Contains(value, ":")
}

func validDNSLAPassword(value string) bool {
	return validDNSLACredential(value)
}

func validDNSLACredential(value string) bool {
	if len(value) < 1 || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
