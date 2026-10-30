package builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTPSource pulls the dnspup customer API tool
// GET /v1/tools/ip-intel-snapshot (dnspup docs/ip-intel-export.md): the same
// file cmd/ipintel-export writes, parsed with ParseDnspupSnapshot (so
// CheckRedistributable applies). Credentials are a dnspup customer API key
// pair (X-API-Key / X-API-Secret) bound to the license service egress IP;
// domain-bound keys (signed requests) are not supported. The request carries
// the last published release as If-None-Match; 304 means nothing to do and
// is not metered by dnspup. Credentials never appear in errors.
type HTTPSourceConfig struct {
	URL       string
	APIKey    string
	APISecret string
	Timeout   time.Duration // whole request incl. body; 0 = 10 minutes
	MaxBytes  int64         // compressed body bound; 0 = DefaultFileSourceMaxBytes
}

var (
	// ErrSourceAuth: dnspup rejected the key pair (401 unauthorized).
	ErrSourceAuth = errors.New("ip intel source rejected the API key")
	// ErrSourceDomainBinding: the key is domain-bound and needs signed
	// requests, which the license service does not send (bind it to an IP).
	ErrSourceDomainBinding = errors.New("ip intel source key needs domain signatures; bind the key to the license service IP")
	// ErrSourceForbidden: the request source IP is not the key's binding (403).
	ErrSourceForbidden = errors.New("ip intel source refused this source address")
	// ErrSourceToolNotAllowed: the key lacks the ip-intel-snapshot tool (403).
	ErrSourceToolNotAllowed = errors.New("ip intel source key is not granted the ip-intel-snapshot tool")
	// ErrSourceQuota: the key's monthly quota is used up (429 quota_exceeded).
	ErrSourceQuota = errors.New("ip intel source monthly quota exceeded")
	// ErrSourceTooLarge: the body is over MaxBytes.
	ErrSourceTooLarge = errors.New("ip intel source body too large")
	// ErrSourcePending: dnspup is generating the snapshot, busy, rate
	// limited or not ready (503 / 429 other than quota).
	ErrSourcePending = errors.New("ip intel source is not ready")
	// ErrSourceUnreachable: transport failure, timeout or an unexpected
	// HTTP status (the body, if any, was not a snapshot).
	ErrSourceUnreachable = errors.New("ip intel source unreachable")
)

const (
	minHTTPSourceKeyLength    = 8
	minHTTPSourceSecretLength = 16
	maxHTTPSourceCredential   = 512
)

// FetchResult is one pull. NotModified: the known release is current.
type FetchResult struct {
	Status      int
	NotModified bool
	Release     string
	Collection  Collection
	SHA256      string // compressed body
	Bytes       int64
	RetryAfter  time.Duration // from 429 / 503
	ErrorCode   string        // dnspup error.code / X-API-Error-Code, if any
}

// ProbeResult is a HEAD check (not metered by dnspup): the credentials,
// source binding and tool grant are accepted and the current release is known.
type ProbeResult struct {
	Status     int
	Release    string
	State      string // ready | pending (X-IP-Intel-Status)
	Bytes      int64
	RetryAfter time.Duration
	ErrorCode  string
}

type HTTPSource struct {
	url       string
	apiKey    string
	apiSecret string
	timeout   time.Duration
	maxBytes  int64
	client    *http.Client
}

// ValidHTTPSourceURL checks the endpoint: https (http only to a loopback
// host, for tests and local proxies), no credentials, query secrets or
// fragment.
func ValidHTTPSourceURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopbackHost(parsed.Hostname()))) {
		return nil, errors.New("ip intel pull URL must be https:// without credentials (http only for loopback)")
	}
	return parsed, nil
}

// ValidHTTPSourceCredential reports whether value is a usable header value
// of at least minimum printable ASCII characters without spaces.
func ValidHTTPSourceCredential(value string, minimum int) bool {
	return len(value) >= minimum && len(value) <= maxHTTPSourceCredential &&
		strings.IndexFunc(value, func(r rune) bool { return r <= ' ' || r > '~' }) < 0
}

// NewHTTPSource checks the configuration (URL as ValidHTTPSourceURL, an API
// key of at least 8 and a secret of at least 16 printable characters).
func NewHTTPSource(config HTTPSourceConfig) (*HTTPSource, error) {
	parsed, err := ValidHTTPSourceURL(config.URL)
	if err != nil {
		return nil, err
	}
	if !ValidHTTPSourceCredential(config.APIKey, minHTTPSourceKeyLength) {
		return nil, fmt.Errorf("ip intel pull API key must be %d-%d printable characters", minHTTPSourceKeyLength, maxHTTPSourceCredential)
	}
	if !ValidHTTPSourceCredential(config.APISecret, minHTTPSourceSecretLength) {
		return nil, fmt.Errorf("ip intel pull API secret must be %d-%d printable characters", minHTTPSourceSecretLength, maxHTTPSourceCredential)
	}
	source := &HTTPSource{url: parsed.String(), apiKey: config.APIKey, apiSecret: config.APISecret, timeout: config.Timeout,
		maxBytes: config.MaxBytes,
		client:   &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if source.timeout <= 0 {
		source.timeout = 10 * time.Minute
	}
	if source.maxBytes <= 0 {
		source.maxBytes = DefaultFileSourceMaxBytes
	}
	return source, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// URL is the configured endpoint (no credential in it).
func (source *HTTPSource) URL() string { return source.url }

func (source *HTTPSource) newRequest(ctx context.Context, method string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, source.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrSource)
	}
	request.Header.Set("X-API-Key", source.apiKey)
	request.Header.Set("X-API-Secret", source.apiSecret)
	request.Header.Set("Accept", "application/gzip")
	request.Header.Set("User-Agent", "cdnca-license-service ip-intel-pull")
	return request, nil
}

func (source *HTTPSource) do(ctx context.Context, request *http.Request) (*http.Response, error) {
	response, err := source.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %w", ErrSourceUnreachable, ctx.Err())
		}
		return nil, fmt.Errorf("%w: request failed: %s", ErrSourceUnreachable, transportError(err))
	}
	return response, nil
}

// statusError maps a non-200/304 dnspup answer to a sentinel error, the
// dnspup error code and Retry-After.
func statusError(response *http.Response) (error, string, time.Duration) {
	code := apiErrorCode(response)
	label := fmt.Sprintf("HTTP %d", response.StatusCode)
	if code != "" {
		label += " (" + code + ")"
	}
	wait := retryAfter(response.Header.Get("Retry-After"))
	switch status := response.StatusCode; {
	case status == http.StatusUnauthorized && (code == "" || code == "unauthorized"):
		return fmt.Errorf("%w: %s", ErrSourceAuth, label), code, 0
	case status == http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", ErrSourceDomainBinding, label), code, 0
	case status == http.StatusForbidden && code == "tool_not_allowed":
		return fmt.Errorf("%w: %s", ErrSourceToolNotAllowed, label), code, 0
	case status == http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrSourceForbidden, label), code, 0
	case status == http.StatusTooManyRequests && code == "quota_exceeded":
		return fmt.Errorf("%w: %s", ErrSourceQuota, label), code, wait
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		state := response.Header.Get("X-IP-Intel-Status")
		if state != "" {
			label += " " + headerToken(state)
		}
		return fmt.Errorf("%w: %s", ErrSourcePending, label), code, wait
	default:
		return fmt.Errorf("%w: %s", ErrSourceUnreachable, label), code, wait
	}
}

// apiErrorCode reads X-API-Error-Code, or error.code from a small JSON body
// (HEAD has none). Bounded and sanitized: it is shown on the operator page.
func apiErrorCode(response *http.Response) string {
	code := response.Header.Get("X-API-Error-Code")
	if code == "" && response.Body != nil {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if data, err := io.ReadAll(io.LimitReader(response.Body, 4<<10)); err == nil && json.Unmarshal(data, &envelope) == nil {
			code = envelope.Error.Code
		}
	}
	code = strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(code))
	if len(code) > 64 {
		code = code[:64]
	}
	return code
}

// Probe sends HEAD (dnspup does not meter it): checks the key pair, source
// binding and tool grant, and reports the current release without a download.
func (source *HTTPSource) Probe(ctx context.Context) (ProbeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, min(source.timeout, time.Minute))
	defer cancel()
	request, err := source.newRequest(ctx, http.MethodHead)
	if err != nil {
		return ProbeResult{}, err
	}
	response, err := source.do(ctx, request)
	if err != nil {
		return ProbeResult{}, err
	}
	defer response.Body.Close()
	result := ProbeResult{Status: response.StatusCode}
	if response.StatusCode != http.StatusOK {
		err, result.ErrorCode, result.RetryAfter = statusError(response)
		return result, err
	}
	result.Release = headerToken(strings.Trim(strings.TrimPrefix(response.Header.Get("ETag"), "W/"), `"`))
	result.State = headerToken(response.Header.Get("X-IP-Intel-Status"))
	if response.ContentLength > 0 {
		result.Bytes = response.ContentLength
	}
	if result.Release == "" {
		return result, fmt.Errorf("%w: HEAD answered without a release", ErrSourceUnreachable)
	}
	return result, nil
}

// Fetch downloads the snapshot unless known is still current.
func (source *HTTPSource) Fetch(ctx context.Context, known string) (FetchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	request, err := source.newRequest(ctx, http.MethodGet)
	if err != nil {
		return FetchResult{}, err
	}
	if known != "" {
		request.Header.Set("If-None-Match", `"`+known+`"`)
	}
	response, err := source.do(ctx, request)
	if err != nil {
		return FetchResult{}, err
	}
	defer response.Body.Close()
	result := FetchResult{Status: response.StatusCode}
	switch response.StatusCode {
	case http.StatusNotModified:
		result.NotModified, result.Release = true, known
		return result, nil
	case http.StatusOK:
	default:
		err, result.ErrorCode, result.RetryAfter = statusError(response)
		return result, err
	}
	if response.ContentLength > source.maxBytes {
		return result, fmt.Errorf("%w: %d bytes (limit %d)", ErrSourceTooLarge, response.ContentLength, source.maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, source.maxBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return result, fmt.Errorf("%w: read body: %w", ErrSourceUnreachable, ctx.Err())
		}
		return result, fmt.Errorf("%w: read body: %v", ErrSourceUnreachable, err)
	}
	if int64(len(body)) > source.maxBytes {
		return result, fmt.Errorf("%w: over %d bytes", ErrSourceTooLarge, source.maxBytes)
	}
	collection, release, err := ParseDnspupSnapshot(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return result, err
	}
	if etag := strings.Trim(strings.TrimPrefix(response.Header.Get("ETag"), "W/"), `"`); etag != "" && etag != release {
		return result, fmt.Errorf("%w: ETag %q does not match snapshot %q", ErrSource, headerToken(etag), release)
	}
	digest := sha256.Sum256(body)
	result.Release, result.Collection = release, collection
	result.SHA256, result.Bytes = hex.EncodeToString(digest[:]), int64(len(body))
	return result, nil
}

// transportError keeps the error text without the URL (it is shown on the
// operator page) and never includes request headers.
func transportError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return err.Error()
}

func retryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(min(seconds, 24*3600)) * time.Second
}

// headerToken bounds a header value echoed into an error.
func headerToken(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, value)
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
