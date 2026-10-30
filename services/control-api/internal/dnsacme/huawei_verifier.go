package dnsacme

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	huaweiVerifyRequestPath  = "/v2/zones"
	huaweiVerifyCanonicalURI = "/v2/zones/"
	huaweiVerifyQuery        = "limit=1&type=public"
	huaweiVerifyBodySize     = 64 << 10
	huaweiVerifyTimeout      = 5 * time.Second
	huaweiTimestampLayout    = "20060102T150405Z"
	huaweiSigningAlgorithm   = "SDK-HMAC-SHA256"
)

type HuaweiProviderVerifier struct {
	testBaseURL string
	client      *http.Client
	timeout     time.Duration
	now         func() time.Time
}

type huaweiSignedRequest struct {
	CanonicalRequest string
	StringToSign     string
	Authorization    string
}

func NewHuaweiProviderVerifier() *HuaweiProviderVerifier {
	return newHuaweiProviderVerifier("", http.DefaultClient, huaweiVerifyTimeout, time.Now)
}

func newHuaweiProviderVerifier(
	testBaseURL string,
	client *http.Client,
	timeout time.Duration,
	now func() time.Time,
) *HuaweiProviderVerifier {
	if client == nil {
		client = http.DefaultClient
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if timeout <= 0 {
		timeout = huaweiVerifyTimeout
	}
	if now == nil {
		now = time.Now
	}
	return &HuaweiProviderVerifier{
		testBaseURL: strings.TrimRight(testBaseURL, "/"),
		client:      &configuredClient,
		timeout:     timeout,
		now:         now,
	}
}

func (v *HuaweiProviderVerifier) Verify(
	ctx context.Context,
	region string,
	projectID string,
	accessKey string,
	secretKey string,
) error {
	host, ok := huaweiDNSHost(region)
	if !ok {
		return ErrProviderCredentialsInvalid
	}
	baseURL := "https://" + host
	if v.testBaseURL != "" {
		baseURL = v.testBaseURL
	}
	timestamp := v.now().UTC().Format(huaweiTimestampLayout)
	signed := signHuaweiRequest(
		http.MethodGet,
		huaweiVerifyCanonicalURI,
		huaweiVerifyQuery,
		map[string]string{
			"host":         host,
			"x-project-id": projectID,
			"x-sdk-date":   timestamp,
		},
		nil,
		accessKey,
		secretKey,
		timestamp,
	)

	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		baseURL+huaweiVerifyRequestPath+"?"+huaweiVerifyQuery,
		nil,
	)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = host
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", signed.Authorization)
	request.Header.Set("X-Project-Id", projectID)
	request.Header.Set("X-Sdk-Date", timestamp)

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
	case response.StatusCode >= 300 && response.StatusCode <= 399:
		return ErrProviderVerificationInvalidResponse
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, huaweiVerifyBodySize+1))
	var envelope struct {
		ErrorCode string          `json:"error_code"`
		Zones     json.RawMessage `json:"zones"`
		Metadata  *struct {
			TotalCount *int `json:"total_count"`
		} `json:"metadata"`
	}
	validEnvelope := err == nil && len(body) <= huaweiVerifyBodySize
	if validEnvelope {
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		if err := decoder.Decode(&envelope); err != nil {
			validEnvelope = false
		} else if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			validEnvelope = false
		}
	}
	if validEnvelope && huaweiAuthenticationError(envelope.ErrorCode) {
		return ErrProviderCredentialsRejected
	}
	switch {
	case response.StatusCode == http.StatusTooManyRequests:
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		return ErrProviderVerificationUnavailable
	}
	if !validEnvelope {
		return ErrProviderVerificationInvalidResponse
	}
	if response.StatusCode != http.StatusOK || envelope.ErrorCode != "" || len(envelope.Zones) == 0 ||
		envelope.Metadata == nil || envelope.Metadata.TotalCount == nil || *envelope.Metadata.TotalCount < 0 {
		return ErrProviderVerificationInvalidResponse
	}
	var zones []json.RawMessage
	if err := json.Unmarshal(envelope.Zones, &zones); err != nil || zones == nil {
		return ErrProviderVerificationInvalidResponse
	}
	totalCount := *envelope.Metadata.TotalCount
	if len(zones) > totalCount || (totalCount == 0) != (len(zones) == 0) {
		return ErrProviderVerificationInvalidResponse
	}
	for _, zone := range zones {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(zone, &object); err != nil || object == nil {
			return ErrProviderVerificationInvalidResponse
		}
	}
	return nil
}

func signHuaweiRequest(
	method string,
	canonicalURI string,
	canonicalQuery string,
	headers map[string]string,
	payload []byte,
	accessKey string,
	secretKey string,
	timestamp string,
) huaweiSignedRequest {
	headerNames := make([]string, 0, len(headers))
	canonicalHeaders := make(map[string]string, len(headers))
	for name, value := range headers {
		name = strings.ToLower(name)
		headerNames = append(headerNames, name)
		canonicalHeaders[name] = strings.TrimSpace(value)
	}
	sort.Strings(headerNames)
	headerLines := make([]string, 0, len(headerNames))
	for _, name := range headerNames {
		headerLines = append(headerLines, name+":"+canonicalHeaders[name])
	}
	signedHeaders := strings.Join(headerNames, ";")
	payloadDigest := sha256.Sum256(payload)
	canonicalRequest := fmt.Sprintf(
		"%s\n%s\n%s\n%s\n\n%s\n%s",
		method,
		canonicalURI,
		canonicalQuery,
		strings.Join(headerLines, "\n"),
		signedHeaders,
		hex.EncodeToString(payloadDigest[:]),
	)
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := huaweiSigningAlgorithm + "\n" + timestamp + "\n" + hex.EncodeToString(canonicalDigest[:])
	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))
	return huaweiSignedRequest{
		CanonicalRequest: canonicalRequest,
		StringToSign:     stringToSign,
		Authorization: fmt.Sprintf(
			"%s Access=%s, SignedHeaders=%s, Signature=%s",
			huaweiSigningAlgorithm,
			accessKey,
			signedHeaders,
			signature,
		),
	}
}

func huaweiAuthenticationError(code string) bool {
	return strings.HasPrefix(code, "APIGW.03")
}

func huaweiDNSHost(region string) (string, bool) {
	switch region {
	case "cn-north-4":
		return "dns.cn-north-4.myhuaweicloud.com", true
	case "ap-southeast-3":
		return "dns.ap-southeast-3.myhuaweicloud.com", true
	default:
		return "", false
	}
}
