package dnsproviderremote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	responseBodyLimit = 64 << 10
	userAgent         = "cdnca-control-api/dns-provider-remote-txt"
	maxRetryAfter     = time.Hour
)

type endpoint struct {
	baseURL string
	host    string
}

type endpointSet struct {
	cloudflare endpoint
	aliyun     endpoint
	huawei     map[string]endpoint
	dnspod     endpoint
	dnscom     endpoint
	dnsla      endpoint
	namecom    endpoint
}

func productionEndpoints() endpointSet {
	return endpointSet{
		cloudflare: endpoint{baseURL: "https://api.cloudflare.com/client/v4", host: "api.cloudflare.com"},
		aliyun:     endpoint{baseURL: "https://alidns.aliyuncs.com", host: "alidns.aliyuncs.com"},
		huawei: map[string]endpoint{
			"cn-north-4":     {baseURL: "https://dns.cn-north-4.myhuaweicloud.com", host: "dns.cn-north-4.myhuaweicloud.com"},
			"ap-southeast-3": {baseURL: "https://dns.ap-southeast-3.myhuaweicloud.com", host: "dns.ap-southeast-3.myhuaweicloud.com"},
		},
		dnspod: endpoint{baseURL: "https://dnsapi.cn", host: "dnsapi.cn"},
		dnscom: endpoint{baseURL: "https://openapi.dns.com", host: "openapi.dns.com"},
		dnsla:  endpoint{baseURL: "https://api.dns.la", host: "api.dns.la"},
		// name.com Core API production host (sandbox: api.dev.name.com).
		namecom: endpoint{baseURL: "https://api.name.com", host: "api.name.com"},
	}
}

type boundedHTTPClient struct {
	client  *http.Client
	timeout time.Duration
}

type httpResponse struct {
	status         int
	header         http.Header
	body           []byte
	bodyReadFailed bool
}

func newBoundedHTTPClient(transport http.RoundTripper, timeout time.Duration) *boundedHTTPClient {
	if transport == nil {
		configured := http.DefaultTransport.(*http.Transport).Clone()
		configured.Proxy = nil
		transport = configured
	} else if configured, ok := transport.(*http.Transport); ok {
		cloned := configured.Clone()
		cloned.Proxy = nil
		transport = cloned
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &boundedHTTPClient{client: client, timeout: timeout}
}

func (c *boundedHTTPClient) do(
	ctx context.Context,
	method string,
	endpoint endpoint,
	pathAndQuery string,
	body []byte,
	headers http.Header,
) (httpResponse, error) {
	if ctx == nil || c == nil || c.client == nil || c.timeout <= 0 || !validEndpoint(endpoint) ||
		!strings.HasPrefix(pathAndQuery, "/") {
		return httpResponse{}, failure(CodeInvalidInput, false)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, endpoint.baseURL+pathAndQuery, bytes.NewReader(body))
	if err != nil {
		return httpResponse{}, failure(CodeInvalidInput, false)
	}
	request.Host = endpoint.host
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return httpResponse{}, contextFailure(ctx.Err())
		}
		if errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			return httpResponse{}, failure(CodeTimeout, true)
		}
		return httpResponse{}, failure(CodeUnavailable, true)
	}
	defer response.Body.Close()
	return boundedHTTPResponse(response), nil
}

func boundedHTTPResponse(response *http.Response) httpResponse {
	result := httpResponse{status: response.StatusCode, header: response.Header.Clone()}
	body, err := io.ReadAll(io.LimitReader(response.Body, responseBodyLimit+1))
	if err != nil || len(body) > responseBodyLimit {
		result.bodyReadFailed = true
		return result
	}
	result.body = body
	return result
}

func validEndpoint(endpoint endpoint) bool {
	parsed, err := url.Parse(endpoint.baseURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && endpoint.host != "" &&
		!strings.ContainsAny(endpoint.host, "/?#@")
}

func classifyHTTP(response httpResponse, now time.Time) error {
	switch {
	case response.status == http.StatusRequestTimeout:
		return failure(CodeTimeout, true)
	case response.status == http.StatusUnauthorized || response.status == http.StatusForbidden:
		return failure(CodeCredentialsRejected, false)
	case response.status == http.StatusTooManyRequests:
		return rateLimitFailure(response.header.Get("Retry-After"), now)
	case response.status >= 500 && response.status <= 599:
		return failure(CodeUnavailable, true)
	case response.status >= 300 && response.status <= 399:
		return malformedProviderResponse()
	case response.bodyReadFailed:
		return malformedProviderResponse()
	default:
		return nil
	}
}

func rateLimitFailure(raw string, now time.Time) *Error {
	return &Error{Code: CodeRateLimited, RetryAfter: parseRetryAfter(raw, now), Temporary: true}
}

func parseRetryAfter(raw string, now time.Time) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(raw, 10, 64); err == nil {
		if seconds > uint64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(raw); err == nil {
		delay := when.Sub(now)
		if delay > maxRetryAfter {
			return maxRetryAfter
		}
		if delay > 0 {
			return delay
		}
	}
	return 0
}

func decodeJSON(body []byte, target any) error {
	if len(body) == 0 {
		return malformedProviderResponse()
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return malformedProviderResponse()
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return malformedProviderResponse()
	}
	return nil
}

type stringID string

func (id *stringID) UnmarshalJSON(raw []byte) error {
	var stringValue string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &stringValue); err != nil || !validReference(stringValue, 256) {
			return errors.New("invalid identifier")
		}
		*id = stringID(stringValue)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return errors.New("invalid identifier")
	}
	value := number.String()
	if value == "" || strings.ContainsAny(value, ".eE+-") {
		return errors.New("invalid identifier")
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return errors.New("invalid identifier")
	}
	*id = stringID(value)
	return nil
}
