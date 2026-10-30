package dnsacme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	cloudflareAPIBaseURL     = "https://api.cloudflare.com/client/v4"
	cloudflareVerifyBodySize = 64 << 10
	cloudflareVerifyTimeout  = 5 * time.Second
)

type ProviderVerifier interface {
	Verify(context.Context, string, string) error
}

type CloudflareProviderVerifier struct {
	baseURL string
	client  *http.Client
	timeout time.Duration
}

type providerVerificationRetryError struct {
	retryAfter string
}

func (e *providerVerificationRetryError) Error() string {
	return ErrProviderVerificationRateLimited.Error()
}
func (e *providerVerificationRetryError) Unwrap() error { return ErrProviderVerificationRateLimited }

func NewCloudflareProviderVerifier() *CloudflareProviderVerifier {
	return newCloudflareProviderVerifier(cloudflareAPIBaseURL, http.DefaultClient, cloudflareVerifyTimeout)
}

func newCloudflareProviderVerifier(baseURL string, client *http.Client, timeout time.Duration) *CloudflareProviderVerifier {
	if client == nil {
		client = http.DefaultClient
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if timeout <= 0 {
		timeout = cloudflareVerifyTimeout
	}
	return &CloudflareProviderVerifier{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &configuredClient,
		timeout: timeout,
	}
}

func (v *CloudflareProviderVerifier) Verify(ctx context.Context, providerType, apiToken string) error {
	if providerType != "cloudflare" {
		return ErrProviderVerificationUnsupported
	}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, v.baseURL+"/user/tokens/verify", nil)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+apiToken)
	request.Header.Set("Accept", "application/json")

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

	body, bodyErr := io.ReadAll(io.LimitReader(response.Body, cloudflareVerifyBodySize+1))
	var envelope struct {
		Success bool `json:"success"`
		Result  struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"result"`
		Errors []struct {
			Code int `json:"code"`
		} `json:"errors"`
	}
	decoded := false
	if bodyErr == nil && len(body) <= cloudflareVerifyBodySize {
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		if err := decoder.Decode(&envelope); err == nil {
			decoded = errors.Is(decoder.Decode(&struct{}{}), io.EOF)
		}
	}
	credentialRejected := false
	rateLimited := false
	if decoded {
		for _, providerError := range envelope.Errors {
			switch providerError.Code {
			case 9109, 10000:
				credentialRejected = true
			case 1015:
				rateLimited = true
			}
		}
	}
	if credentialRejected {
		return ErrProviderCredentialsRejected
	}
	if rateLimited {
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
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
	if !envelope.Success {
		return ErrProviderCredentialsRejected
	}
	if envelope.Result.Status != "active" {
		return ErrProviderTokenInactive
	}
	if strings.TrimSpace(envelope.Result.ID) == "" {
		return ErrProviderVerificationInvalidResponse
	}
	return nil
}

func ProviderVerificationRetryAfter(err error) string {
	var retryError *providerVerificationRetryError
	if errors.As(err, &retryError) {
		return retryError.retryAfter
	}
	return ""
}

func validRetryAfter(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if seconds, err := strconv.ParseUint(raw, 10, 31); err == nil {
		return strconv.FormatUint(seconds, 10)
	}
	if parsed, err := http.ParseTime(raw); err == nil {
		return parsed.UTC().Format(http.TimeFormat)
	}
	return ""
}
