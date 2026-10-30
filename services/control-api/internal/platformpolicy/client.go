package platformpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultHTTPTimeout      = 15 * time.Second
	maxErrorBytes           = 16 * 1024
	maxAckResponseBytes     = 16 * 1024
	maxResolveResponseBytes = 2*maxSignedPolicyBytes + 32*1024
)

var (
	ErrInvalidClient   = errors.New("invalid platform policy client configuration")
	ErrInvalidResponse = errors.New("invalid platform policy service response")
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	baseURL *url.URL
	http    HTTPClient
}

type ServiceError struct {
	StatusCode int
	Code       string
	RetryAfter time.Duration
}

func (err *ServiceError) Error() string {
	if err.Code == "" {
		return fmt.Sprintf("platform policy service returned HTTP %d", err.StatusCode)
	}
	return fmt.Sprintf("platform policy service returned HTTP %d (%s)", err.StatusCode, err.Code)
}

func (err *ServiceError) Retryable() bool {
	return err.StatusCode == http.StatusTooManyRequests || err.StatusCode >= http.StatusInternalServerError
}

type ResolvedTarget struct {
	Signed  SignedPlatformPolicy
	Encoded []byte
}

type ResolveResult struct {
	ResolvedAt  time.Time
	Cursor      string
	ETag        string
	NotModified bool
	Targets     []ResolvedTarget
}

type AckResult struct {
	AcknowledgementID uuid.UUID
	AcceptedStatus    string
	ReceivedAt        time.Time
}

func NewClient(rawBaseURL string, httpClient HTTPClient) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, ErrInvalidClient
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       defaultHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

func (client *Client) Resolve(ctx context.Context, input ResolveInput,
	privateKey ed25519.PrivateKey, now time.Time) (ResolveResult, error) {
	requestID := "control-policy-resolve-" + uuid.NewString()
	payload, err := PrepareResolve(input, requestID, now, privateKey)
	if err != nil {
		return ResolveResult{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ResolveResult{}, fmt.Errorf("encode platform policy resolve request: %w", err)
	}
	responseBody, err := client.post(ctx, "/installation/v1/platform-policies:resolve", requestID,
		encoded, maxResolveResponseBytes)
	for index := range encoded {
		encoded[index] = 0
	}
	if err != nil {
		return ResolveResult{}, err
	}
	return decodeResolveResponse(responseBody, requestID, input.InstallationID)
}

func (client *Client) Acknowledge(ctx context.Context, input AckInput,
	privateKey ed25519.PrivateKey, now time.Time) (AckResult, error) {
	requestID := "control-policy-ack-" + uuid.NewString()
	payload, err := PrepareAcknowledgement(input, requestID, now, privateKey)
	if err != nil {
		return AckResult{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return AckResult{}, fmt.Errorf("encode platform policy acknowledgement: %w", err)
	}
	responseBody, err := client.post(ctx, "/installation/v1/platform-policy-acknowledgements", requestID,
		encoded, maxAckResponseBytes)
	for index := range encoded {
		encoded[index] = 0
	}
	if err != nil {
		return AckResult{}, err
	}
	return decodeAckResponse(responseBody, requestID, input.Status)
}

func (client *Client) post(ctx context.Context, path, requestID string, body []byte, responseLimit int64) ([]byte, error) {
	if client == nil || client.baseURL == nil || client.http == nil || !validRequestID(requestID) || len(body) == 0 ||
		responseLimit < 1 {
		return nil, ErrInvalidClient
	}
	target := *client.baseURL
	target.Path += path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create platform policy request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send platform policy request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, decodeServiceError(response)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if mediaErr != nil || mediaType != "application/json" || readErr != nil || len(encoded) == 0 ||
		int64(len(encoded)) > responseLimit || !json.Valid(encoded) || rejectDuplicateKeys(encoded) != nil {
		return nil, ErrInvalidResponse
	}
	return encoded, nil
}

func decodeResolveResponse(encoded []byte, requestID string, installationID uuid.UUID) (ResolveResult, error) {
	var wire struct {
		Schema         string            `json:"schema"`
		RequestID      string            `json:"request_id"`
		InstallationID string            `json:"installation_id"`
		ResolvedAt     int64             `json:"resolved_at"`
		Cursor         string            `json:"cursor"`
		ETag           string            `json:"etag"`
		NotModified    bool              `json:"not_modified"`
		Targets        []json.RawMessage `json:"targets"`
	}
	if decodeStrict(encoded, &wire) != nil || wire.Schema != ResolveResponseSchema || wire.RequestID != requestID ||
		wire.InstallationID != installationID.String() || wire.ResolvedAt < 1 || wire.ResolvedAt > maxUnixTimestamp ||
		len(wire.Cursor) > 512 || len(wire.ETag) > 128 || len(wire.Targets) > 2 || wire.NotModified != (len(wire.Targets) == 0) {
		return ResolveResult{}, ErrInvalidResponse
	}
	result := ResolveResult{ResolvedAt: time.Unix(wire.ResolvedAt, 0).UTC(), Cursor: wire.Cursor,
		ETag: wire.ETag, NotModified: wire.NotModified, Targets: make([]ResolvedTarget, 0, len(wire.Targets))}
	previousScope := ""
	for _, raw := range wire.Targets {
		signed, err := Decode(raw)
		if err != nil {
			return ResolveResult{}, ErrInvalidResponse
		}
		if (previousScope == ScopeInstallation && signed.Envelope.ScopeKind == ScopeGlobal) ||
			(previousScope == signed.Envelope.ScopeKind) {
			return ResolveResult{}, ErrInvalidResponse
		}
		previousScope = signed.Envelope.ScopeKind
		result.Targets = append(result.Targets, ResolvedTarget{Signed: signed, Encoded: append([]byte(nil), raw...)})
	}
	return result, nil
}

func decodeAckResponse(encoded []byte, requestID, status string) (AckResult, error) {
	var wire struct {
		Schema            string `json:"schema"`
		RequestID         string `json:"request_id"`
		AcknowledgementID string `json:"acknowledgement_id"`
		AcceptedStatus    string `json:"accepted_status"`
		ReceivedAt        int64  `json:"received_at"`
	}
	if decodeStrict(encoded, &wire) != nil {
		return AckResult{}, ErrInvalidResponse
	}
	ackID, idErr := uuid.Parse(wire.AcknowledgementID)
	if wire.Schema != AckResponseSchema || wire.RequestID != requestID || wire.AcceptedStatus != status ||
		idErr != nil || ackID == uuid.Nil || ackID.String() != wire.AcknowledgementID ||
		wire.ReceivedAt < 1 || wire.ReceivedAt > maxUnixTimestamp {
		return AckResult{}, ErrInvalidResponse
	}
	return AckResult{AcknowledgementID: ackID, AcceptedStatus: wire.AcceptedStatus,
		ReceivedAt: time.Unix(wire.ReceivedAt, 0).UTC()}, nil
}

func decodeServiceError(response *http.Response) error {
	limited := io.LimitReader(response.Body, maxErrorBytes)
	var wire struct {
		Code  string `json:"code"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.NewDecoder(limited).Decode(&wire)
	code := wire.Code
	if code == "" {
		code = wire.Error.Code
	}
	if !codePattern.MatchString(code) {
		code = ""
	}
	return &ServiceError{StatusCode: response.StatusCode, Code: code,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if deadline, err := http.ParseTime(value); err == nil && deadline.After(now) {
		return deadline.Sub(now)
	}
	return 0
}

func retryable(err error) (time.Duration, bool) {
	var serviceError *ServiceError
	if errors.As(err, &serviceError) {
		return serviceError.RetryAfter, serviceError.Retryable()
	}
	return 0, true
}
