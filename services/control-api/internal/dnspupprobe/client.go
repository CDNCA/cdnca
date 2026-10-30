// Package dnspupprobe is the official plugin module.probe.dnspup: the platform's own dnspup customer API key pair probes origins
// and supplies from dnspup's checkpoints, as a probe source next to the
// tenant's nodes (MARKET_PROBE v3) and the control plane's direct probe.
//
// dnspup customer API (source of truth: dnspup backend/internal/httpapi
// customer_api.go, customer_api_jobs.go): X-API-Key + X-API-Secret; a key
// bound to a server domain also signs every request (X-API-Source-Domain,
// X-API-Timestamp, X-API-Nonce, X-API-Signature). GET /v1/account reports
// capabilities.asyncProbesV1; POST /v1/probes with Prefer: respond-async and
// an Idempotency-Key creates a job (202; the same key and body again: 200, no
// new charge); GET /v1/probes/{requestId} reads it (180 per key and minute,
// Retry-After 2 while queued/running, results kept 24 hours).
package dnspupprobe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is dnspup's customer API.
const DefaultBaseURL = "https://api.dnspup.com"

const (
	maxResponseBytes = 1 << 20
	requestTimeout   = 15 * time.Second
	signingContext   = "dnspup-customer-api-signing/v1\x00"
	canonicalPrefix  = "dnspup-customer-api-v1"
)

// Credentials is one dnspup key pair; SourceDomain is set for a key bound to
// a server domain (requests are then signed), empty for an IP-bound key.
type Credentials struct {
	BaseURL, APIKey, APISecret, SourceDomain string
}

// APIError is a dnspup error answer.
type APIError struct {
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (err *APIError) Error() string {
	return fmt.Sprintf("dnspup: HTTP %d %s", err.Status, err.Code)
}

// ErrTransport is a request that got no dnspup answer.
var ErrTransport = errors.New("dnspup: transport error")

// Account is GET /v1/account (the key projection and capabilities).
type Account struct {
	Name               string          `json:"name"`
	Plan               string          `json:"plan"`
	Enabled            bool            `json:"enabled"`
	MonthlyLimit       int64           `json:"monthlyLimit"`
	MonthlyUsed        int64           `json:"monthlyUsed"`
	ExpiresAt          string          `json:"expiresAt"`
	AllowedTools       []string        `json:"allowedTools"`
	MaxNodes           int             `json:"maxNodes"`
	RateLimitPerMinute int             `json:"rateLimitPerMinute"`
	SourceMode         string          `json:"sourceMode"`
	Capabilities       map[string]bool `json:"capabilities"`
}

// AsyncProbes reports capabilities.asyncProbesV1.
func (account Account) AsyncProbes() bool { return account.Capabilities["asyncProbesV1"] }

// Allows reports whether the key may run tool.
func (account Account) Allows(tool string) bool {
	for _, allowed := range account.AllowedTools {
		if strings.EqualFold(strings.TrimSpace(allowed), tool) {
			return true
		}
	}
	return false
}

// ProbeRequest is the POST /v1/probes body (customerProbeRequest).
type ProbeRequest struct {
	Type      string   `json:"type"`
	Target    string   `json:"target"`
	Port      int      `json:"port,omitempty"`
	Count     int      `json:"count,omitempty"`
	Method    string   `json:"method,omitempty"`
	IPVersion string   `json:"ipVersion,omitempty"`
	NodeIDs   []string `json:"nodeIds,omitempty"`
}

// Result is one checkpoint's answer (models.ProbeResult): status ok / bad /
// unavailable (did not answer in time).
type Result struct {
	NodeID     string `json:"node_id"`
	Region     string `json:"region"`
	Location   string `json:"location"`
	ISP        string `json:"isp"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	TotalTime  int    `json:"total_time"`
	LatencyMS  int    `json:"latency_ms"`
	AvgLatency int    `json:"avg_latency"`
	LossRate   int    `json:"loss_rate"`
	Error      string `json:"error"`
	ErrorCode  string `json:"errorCode"`
}

// Job is a probe job (writeCustomerProbeJob): status queued / running /
// completed / partial / timeout / unknown / failed.
type Job struct {
	RequestID      string `json:"requestId"`
	Status         string `json:"status"`
	CompletedNodes int    `json:"completedNodes"`
	TotalNodes     int    `json:"totalNodes"`
	Result         *struct {
		Results []Result `json:"results"`
	} `json:"result"`
	Error *struct {
		Code string `json:"code"`
	} `json:"error"`
	// RetryAfter is the answer's Retry-After (0: none).
	RetryAfter time.Duration `json:"-"`
	// Created: 202 (a new, charged job); false: an existing job (200).
	Created bool `json:"-"`
}

// Pending reports whether the job is still running.
func (job Job) Pending() bool { return job.Status == "queued" || job.Status == "running" }

// Results are the checkpoints' answers (none while pending).
func (job Job) Results() []Result {
	if job.Result == nil {
		return nil
	}
	return job.Result.Results
}

// Client calls the dnspup customer API with one key pair.
type Client struct {
	credentials Credentials
	base        *url.URL
	http        *http.Client
	now         func() time.Time
}

// ValidBaseURL: https (http only to a loopback host, for tests), no
// credentials, query or fragment.
func ValidBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback(parsed.Hostname()))) {
		return nil, errors.New("dnspup base URL must be https:// (http only for loopback)")
	}
	return parsed, nil
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// ValidCredential: printable ASCII without spaces, minimum..512 characters.
func ValidCredential(value string, minimum int) bool {
	return len(value) >= minimum && len(value) <= 512 &&
		strings.IndexFunc(value, func(r rune) bool { return r <= ' ' || r > '~' }) < 0
}

// NewClient checks the credentials (key ≥ 8, secret ≥ 16 characters).
func NewClient(credentials Credentials, transport http.RoundTripper) (*Client, error) {
	if credentials.BaseURL == "" {
		credentials.BaseURL = DefaultBaseURL
	}
	base, err := ValidBaseURL(credentials.BaseURL)
	if err != nil {
		return nil, err
	}
	if !ValidCredential(credentials.APIKey, 8) || !ValidCredential(credentials.APISecret, 16) {
		return nil, errors.New("dnspup key pair is malformed")
	}
	credentials.SourceDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(credentials.SourceDomain), "."))
	return &Client{credentials: credentials, base: base, now: time.Now, http: &http.Client{Transport: transport,
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Account reads GET /v1/account.
func (client *Client) Account(ctx context.Context) (Account, error) {
	var account Account
	_, err := client.do(ctx, http.MethodGet, "/v1/account", nil, nil, &account)
	return account, err
}

// Checkpoint is one dnspup probe node (GET /v1/nodes).
type Checkpoint struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Region string `json:"region"`
	City   string `json:"city"`
	ISP    string `json:"isp"`
	Status string `json:"status"`
}

// Nodes reads GET /v1/nodes (the checkpoints this key may use; not metered).
func (client *Client) Nodes(ctx context.Context) ([]Checkpoint, error) {
	var nodes []Checkpoint
	_, err := client.do(ctx, http.MethodGet, "/v1/nodes", nil, nil, &nodes)
	return nodes, err
}

// CreateProbe creates (or, for the same key and body, returns) an async job.
func (client *Client) CreateProbe(ctx context.Context, idempotencyKey string, request ProbeRequest) (Job, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return Job{}, err
	}
	var job Job
	headers := http.Header{"Prefer": {"respond-async"}, "Idempotency-Key": {idempotencyKey},
		"Content-Type": {"application/json"}}
	answer, err := client.do(ctx, http.MethodPost, "/v1/probes", body, headers, &job)
	job.RetryAfter, job.Created = answer.retryAfter, answer.status == http.StatusAccepted
	return job, err
}

// GetProbe reads a job.
func (client *Client) GetProbe(ctx context.Context, requestID string) (Job, error) {
	var job Job
	answer, err := client.do(ctx, http.MethodGet, "/v1/probes/"+url.PathEscape(requestID), nil, nil, &job)
	job.RetryAfter = answer.retryAfter
	return job, err
}

type answer struct {
	status     int
	retryAfter time.Duration
}

func (client *Client) do(ctx context.Context, method, path string, body []byte, headers http.Header, target any) (answer, error) {
	address := *client.base
	address.Path = strings.TrimRight(address.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, method, address.String(), bytes.NewReader(body))
	if err != nil {
		return answer{}, err
	}
	for name, values := range headers {
		request.Header[name] = values
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "cdnca-control-api dnspup-probe")
	request.Header.Set("X-API-Key", client.credentials.APIKey)
	request.Header.Set("X-API-Secret", client.credentials.APISecret)
	if client.credentials.SourceDomain != "" {
		if err := client.sign(request, body); err != nil {
			return answer{}, err
		}
	}
	response, err := client.http.Do(request)
	if err != nil {
		return answer{}, fmt.Errorf("%w: %v", ErrTransport, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(raw) > maxResponseBytes {
		return answer{status: response.StatusCode}, fmt.Errorf("%w: response unreadable or too large", ErrTransport)
	}
	result := answer{status: response.StatusCode, retryAfter: parseRetryAfter(response.Header.Get("Retry-After"))}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &envelope)
		code := envelope.Error.Code
		if code == "" {
			code = response.Header.Get("X-API-Error-Code")
		}
		return result, &APIError{Status: response.StatusCode, Code: token(code), RetryAfter: result.retryAfter}
	}
	envelope := struct {
		Data any `json:"data"`
	}{Data: target}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return result, fmt.Errorf("%w: malformed response", ErrTransport)
	}
	return result, nil
}

// sign adds the server-domain signature (authorizeCustomerAPIDomain).
func (client *Client) sign(request *http.Request, body []byte) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	timestamp := strconv.FormatInt(client.now().Unix(), 10)
	nonceHex := hex.EncodeToString(nonce)
	request.Header.Set("X-API-Source-Domain", client.credentials.SourceDomain)
	request.Header.Set("X-API-Timestamp", timestamp)
	request.Header.Set("X-API-Nonce", nonceHex)
	request.Header.Set("X-API-Signature", Signature(client.credentials.APISecret, request.Method, request.URL,
		timestamp, nonceHex, client.credentials.SourceDomain, body))
	return nil
}

// Signature is dnspup's request signature: HMAC-SHA256 with the key derived
// from sha256(secret) over the canonical request.
func Signature(secret, method string, address *url.URL, timestamp, nonce, sourceDomain string, body []byte) string {
	secretSum := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	derive := hmac.New(sha256.New, []byte(hex.EncodeToString(secretSum[:])))
	_, _ = derive.Write([]byte(signingContext))
	bodySum := sha256.Sum256(body)
	path := address.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{canonicalPrefix, strings.ToUpper(method), path, address.RawQuery, timestamp, nonce,
		sourceDomain, hex.EncodeToString(bodySum[:])}, "\n")
	mac := hmac.New(sha256.New, derive.Sum(nil))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func parseRetryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(min(seconds, 24*3600)) * time.Second
}

// token bounds an error code echoed into state and audit.
func token(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(value))
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
