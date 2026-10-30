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

const (
	dnspodVerifyEndpoint  = "https://dnsapi.cn/User.Detail"
	dnspodVerifyHost      = "dnsapi.cn"
	dnspodVerifyBodySize  = 64 << 10
	dnspodVerifyTimeout   = 5 * time.Second
	dnspodVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

type DNSPodProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
}

func NewDNSPodProviderVerifier() *DNSPodProviderVerifier {
	return newDNSPodProviderVerifier("", http.DefaultClient, dnspodVerifyTimeout)
}

func newDNSPodProviderVerifier(
	testEndpoint string,
	client *http.Client,
	timeout time.Duration,
) *DNSPodProviderVerifier {
	if client == nil {
		client = http.DefaultClient
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if timeout <= 0 {
		timeout = dnspodVerifyTimeout
	}
	return &DNSPodProviderVerifier{
		testEndpoint: testEndpoint,
		client:       &configuredClient,
		timeout:      timeout,
	}
}

func (v *DNSPodProviderVerifier) Verify(ctx context.Context, dpID, dpKey string) error {
	form := url.Values{
		"error_on_empty": {"no"},
		"format":         {"json"},
		"lang":           {"en"},
		"login_token":    {dpID + "," + dpKey},
	}.Encode()
	endpoint := dnspodVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}

	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		endpoint,
		strings.NewReader(form),
	)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = dnspodVerifyHost
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", dnspodVerifyUserAgent)

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

	body, bodyErr := io.ReadAll(io.LimitReader(response.Body, dnspodVerifyBodySize+1))
	var envelope struct {
		Status *struct {
			Code string `json:"code"`
		} `json:"status"`
		Info json.RawMessage `json:"info"`
	}
	decoded := false
	if bodyErr == nil && len(body) <= dnspodVerifyBodySize {
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		if err := decoder.Decode(&envelope); err == nil {
			decoded = errors.Is(decoder.Decode(&struct{}{}), io.EOF) &&
				envelope.Status != nil && envelope.Status.Code != ""
		}
	}
	if decoded {
		switch envelope.Status.Code {
		case "-1", "-7", "-8", "85":
			return ErrProviderCredentialsRejected
		case "-2":
			return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
		case "-99":
			return ErrProviderVerificationUnavailable
		}
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return ErrProviderCredentialsRejected
	case response.StatusCode == http.StatusTooManyRequests:
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		return ErrProviderVerificationUnavailable
	case response.StatusCode >= 300 && response.StatusCode <= 399:
		return ErrProviderVerificationInvalidResponse
	}
	if !decoded {
		return ErrProviderVerificationInvalidResponse
	}

	switch envelope.Status.Code {
	case "1":
		if response.StatusCode != http.StatusOK || !validDNSPodInfo(envelope.Info) {
			return ErrProviderVerificationInvalidResponse
		}
		return nil
	default:
		return ErrProviderVerificationInvalidResponse
	}
}

func validDNSPodInfo(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var info struct {
		User json.RawMessage `json:"user"`
	}
	if json.Unmarshal(raw, &info) != nil || len(info.User) == 0 {
		return false
	}
	var user map[string]json.RawMessage
	return json.Unmarshal(info.User, &user) == nil && user != nil
}
