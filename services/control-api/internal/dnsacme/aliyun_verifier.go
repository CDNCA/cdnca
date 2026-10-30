package dnsacme

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	aliyunDNSAPIEndpoint  = "https://alidns.aliyuncs.com"
	aliyunDNSAPIVersion   = "2015-01-09"
	aliyunVerifyBodySize  = 64 << 10
	aliyunVerifyTimeout   = 5 * time.Second
	aliyunTimestampLayout = "2006-01-02T15:04:05Z"
)

type AliyunProviderVerifier struct {
	baseURL string
	client  *http.Client
	timeout time.Duration
	now     func() time.Time
	nonce   func() string
}

func NewAliyunProviderVerifier() *AliyunProviderVerifier {
	return newAliyunProviderVerifier(
		aliyunDNSAPIEndpoint,
		http.DefaultClient,
		aliyunVerifyTimeout,
		time.Now,
		uuid.NewString,
	)
}

func newAliyunProviderVerifier(
	baseURL string,
	client *http.Client,
	timeout time.Duration,
	now func() time.Time,
	nonce func() string,
) *AliyunProviderVerifier {
	if client == nil {
		client = http.DefaultClient
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if timeout <= 0 {
		timeout = aliyunVerifyTimeout
	}
	if now == nil {
		now = time.Now
	}
	if nonce == nil {
		nonce = uuid.NewString
	}
	return &AliyunProviderVerifier{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &configuredClient,
		timeout: timeout,
		now:     now,
		nonce:   nonce,
	}
}

func (v *AliyunProviderVerifier) Verify(ctx context.Context, accessKeyID, accessKeySecret string) error {
	parameters := map[string]string{
		"AccessKeyId":      accessKeyID,
		"Action":           "DescribeDomains",
		"Format":           "JSON",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   v.nonce(),
		"SignatureVersion": "1.0",
		"Timestamp":        v.now().UTC().Format(aliyunTimestampLayout),
		"Version":          aliyunDNSAPIVersion,
	}
	canonicalQuery := aliyunCanonicalQuery(parameters)
	stringToSign := "GET&%2F&" + aliyunPercentEncode(canonicalQuery)
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		v.baseURL+"/?"+canonicalQuery+"&Signature="+aliyunPercentEncode(signature),
		nil,
	)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
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

	body, bodyErr := io.ReadAll(io.LimitReader(response.Body, aliyunVerifyBodySize+1))
	var envelope struct {
		RequestID  string `json:"RequestId"`
		Code       string `json:"Code"`
		TotalCount *int   `json:"TotalCount"`
		Domains    *struct {
			Domain []json.RawMessage `json:"Domain"`
		} `json:"Domains"`
	}
	decoded := false
	if bodyErr == nil && len(body) <= aliyunVerifyBodySize {
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		if err := decoder.Decode(&envelope); err == nil {
			decoded = errors.Is(decoder.Decode(&struct{}{}), io.EOF)
		}
	}
	if decoded && aliyunAuthenticationError(envelope.Code) {
		return ErrProviderCredentialsRejected
	}
	if decoded && aliyunRateLimitError(envelope.Code) {
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
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
	if response.StatusCode != http.StatusOK || envelope.Code != "" || envelope.RequestID == "" {
		return ErrProviderVerificationInvalidResponse
	}
	if envelope.TotalCount == nil || *envelope.TotalCount < 0 || envelope.Domains == nil || envelope.Domains.Domain == nil {
		return ErrProviderVerificationInvalidResponse
	}
	totalCount := *envelope.TotalCount
	if len(envelope.Domains.Domain) > totalCount || (totalCount == 0) != (len(envelope.Domains.Domain) == 0) {
		return ErrProviderVerificationInvalidResponse
	}
	for _, domain := range envelope.Domains.Domain {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(domain, &object); err != nil || object == nil {
			return ErrProviderVerificationInvalidResponse
		}
	}
	return nil
}

func aliyunCanonicalQuery(parameters map[string]string) string {
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, aliyunPercentEncode(key)+"="+aliyunPercentEncode(parameters[key]))
	}
	return strings.Join(parts, "&")
}

func aliyunPercentEncode(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var encoded strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' || character == '~' {
			encoded.WriteByte(character)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexadecimal[character>>4])
		encoded.WriteByte(hexadecimal[character&0x0f])
	}
	return encoded.String()
}

func aliyunAuthenticationError(code string) bool {
	switch code {
	case "Forbidden", "Forbidden.RAM", "IncompleteSignature", "NoPermission", "SignatureDoesNotMatch":
		return true
	default:
		return strings.HasPrefix(code, "InvalidAccessKeyId.") || strings.HasPrefix(code, "InvalidSecurityToken")
	}
}

func aliyunRateLimitError(code string) bool {
	return code == "Throttling" || strings.HasPrefix(code, "Throttling.")
}
