package dnsacme

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

// JD Cloud DNS credential check (read 2026-11-05: docs.jdcloud.com
// /cn/jd-cloud-dns/api/describedomains, common error codes): a signed
// GET /v2/regions/cn-north-1/domain?pageNumber=1&pageSize=10 on
// domainservice. 200 without an error accepts; 401 UNAUTHENTICATED / 403
// HTTP_FORBIDDEN reject. The signature is dnsproviderremote.JDCloudSignature
// (one implementation, tested with the official example).
const (
	jdCloudVerifyEndpoint  = "https://domainservice.jdcloud-api.com"
	jdCloudVerifyHost      = "domainservice.jdcloud-api.com"
	jdCloudVerifyPath      = "/v2/regions/cn-north-1/domain"
	jdCloudVerifyBodySize  = 256 << 10
	jdCloudVerifyTimeout   = 5 * time.Second
	jdCloudVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

type JDCloudProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
	now          func() time.Time
}

func NewJDCloudProviderVerifier() *JDCloudProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newJDCloudProviderVerifier("", &http.Client{Transport: transport}, jdCloudVerifyTimeout)
}

func newJDCloudProviderVerifier(testEndpoint string, client *http.Client, timeout time.Duration) *JDCloudProviderVerifier {
	if client == nil {
		client = &http.Client{}
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if timeout <= 0 {
		timeout = jdCloudVerifyTimeout
	}
	return &JDCloudProviderVerifier{testEndpoint: testEndpoint, client: &configuredClient, timeout: timeout, now: time.Now}
}

func (v *JDCloudProviderVerifier) Verify(ctx context.Context, accessKeyID, accessKeySecret string) error {
	if !validDNSComCredential(accessKeyID, 128, false) || !validDNSComCredential(accessKeySecret, 256, false) {
		return ErrProviderCredentialsInvalid
	}
	endpoint := jdCloudVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return ErrProviderVerificationUnavailable
	}
	at := v.now()
	query := url.Values{"pageNumber": {"1"}, "pageSize": {"10"}}
	signed := map[string]string{"content-type": "application/json", "host": jdCloudVerifyHost,
		"x-jdcloud-date": at.UTC().Format("20060102T150405Z"), "x-jdcloud-nonce": hex.EncodeToString(nonce)}
	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet,
		endpoint+jdCloudVerifyPath+"?pageNumber=1&pageSize=10", nil)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = jdCloudVerifyHost
	for name, value := range signed {
		if name != "host" {
			request.Header.Set(name, value)
		}
	}
	request.Header.Set("x-jdcloud-algorithm", "JDCLOUD2-HMAC-SHA256")
	request.Header.Set("Authorization", dnsproviderremote.JDCloudSignature(accessKeyID, accessKeySecret, "cn-north-1",
		"domainservice", http.MethodGet, jdCloudVerifyPath, query, signed, nil, at))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", jdCloudVerifyUserAgent)
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
	body, err := io.ReadAll(io.LimitReader(response.Body, jdCloudVerifyBodySize+1))
	if err != nil || len(body) > jdCloudVerifyBodySize {
		return ErrProviderVerificationInvalidResponse
	}
	var envelope struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	status := response.StatusCode
	if json.Unmarshal(body, &envelope) == nil && envelope.Error != nil && envelope.Error.Code != 0 {
		status = envelope.Error.Code
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrProviderCredentialsRejected
	case status == http.StatusTooManyRequests:
		return &providerVerificationRetryError{retryAfter: validRetryAfter(response.Header.Get("Retry-After"))}
	case status >= 500 && status <= 599:
		return ErrProviderVerificationUnavailable
	case status != http.StatusOK || len(envelope.Result) == 0:
		return ErrProviderVerificationInvalidResponse
	}
	return nil
}

func exactJDCloudCredentials(credentials map[string]string) (string, string, error) {
	if len(credentials) != 2 {
		return "", "", ErrProviderCredentialsInvalid
	}
	accessKeyID, idExists := credentials["access_key_id"]
	accessKeySecret, secretExists := credentials["access_key_secret"]
	if !idExists || !secretExists || !validDNSComCredential(accessKeyID, 128, false) ||
		!validDNSComCredential(accessKeySecret, 256, false) {
		return "", "", ErrProviderCredentialsInvalid
	}
	return accessKeyID, accessKeySecret, nil
}
