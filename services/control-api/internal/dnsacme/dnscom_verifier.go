package dnsacme

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	dnscomVerifyEndpoint  = "https://openapi.dns.com/api/domain/lists/"
	dnscomVerifyHost      = "openapi.dns.com"
	dnscomVerifyBodySize  = 64 << 10
	dnscomVerifyTimeout   = 5 * time.Second
	dnscomVerifyUserAgent = "cdnca-control-api/dns-provider-verifier"
)

type DNSComProviderVerifier struct {
	testEndpoint string
	client       *http.Client
	timeout      time.Duration
	now          func() time.Time
}

func NewDNSComProviderVerifier() *DNSComProviderVerifier {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newDNSComProviderVerifier("", &http.Client{Transport: transport}, dnscomVerifyTimeout, time.Now)
}

func newDNSComProviderVerifier(
	testEndpoint string,
	client *http.Client,
	timeout time.Duration,
	now func() time.Time,
) *DNSComProviderVerifier {
	if client == nil {
		client = http.DefaultClient
	}
	configuredClient := *client
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if timeout <= 0 {
		timeout = dnscomVerifyTimeout
	}
	if now == nil {
		now = time.Now
	}
	return &DNSComProviderVerifier{
		testEndpoint: testEndpoint,
		client:       &configuredClient,
		timeout:      timeout,
		now:          now,
	}
}

func (v *DNSComProviderVerifier) Verify(ctx context.Context, apiKey, apiSecret string) error {
	if !validDNSComCredential(apiKey, 128, true) || !validDNSComCredential(apiSecret, 256, false) {
		return ErrProviderCredentialsInvalid
	}
	parameters := map[string]string{
		"api_key":   apiKey,
		"page":      "1",
		"paginate":  "1",
		"timestamp": strconv.FormatInt(v.now().UTC().Unix(), 10),
	}
	query := make(url.Values, len(parameters)+1)
	for name, value := range parameters {
		query.Set(name, value)
	}
	query.Set("sign", signDNSComRequest(parameters, apiSecret))
	endpoint := dnscomVerifyEndpoint
	if v.testEndpoint != "" {
		endpoint = v.testEndpoint
	}

	requestContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		endpoint+"?"+query.Encode(),
		nil,
	)
	if err != nil {
		return ErrProviderVerificationUnavailable
	}
	request.Host = dnscomVerifyHost
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", dnscomVerifyUserAgent)

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
	case response.StatusCode >= 300 && response.StatusCode <= 399:
		return ErrProviderVerificationInvalidResponse
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, dnscomVerifyBodySize+1))
	if err != nil || len(body) > dnscomVerifyBodySize {
		return ErrProviderVerificationInvalidResponse
	}
	var envelope struct {
		Code *int            `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(&envelope); err != nil {
		return ErrProviderVerificationInvalidResponse
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrProviderVerificationInvalidResponse
	}
	if envelope.Code == nil {
		return ErrProviderVerificationInvalidResponse
	}
	if response.StatusCode != http.StatusOK || *envelope.Code != 0 || !validDNSComDomainList(envelope.Data) {
		return ErrProviderVerificationInvalidResponse
	}
	return nil
}

func signDNSComRequest(parameters map[string]string, apiSecret string) string {
	canonical := canonicalDNSComParameters(parameters)
	digest := md5.Sum([]byte(canonical + apiSecret))
	return hex.EncodeToString(digest[:])
}

func canonicalDNSComParameters(parameters map[string]string) string {
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+parameters[key])
	}
	return strings.Join(parts, "&")
}

func validDNSComDomainList(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var data struct {
		Total   *int            `json:"total"`
		Domains json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &data) != nil || data.Total == nil || *data.Total < 0 || len(data.Domains) == 0 {
		return false
	}
	var domains []json.RawMessage
	if json.Unmarshal(data.Domains, &domains) != nil || domains == nil || len(domains) > *data.Total {
		return false
	}
	if (*data.Total == 0) != (len(domains) == 0) {
		return false
	}
	for _, domain := range domains {
		var object map[string]json.RawMessage
		if json.Unmarshal(domain, &object) != nil || object == nil {
			return false
		}
	}
	return true
}
