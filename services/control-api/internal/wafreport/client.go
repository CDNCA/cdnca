package wafreport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

	"github.com/google/uuid"
)

const maxResponseBytes = 1 << 20

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	baseURL *url.URL
	http    HTTPClient
}

type HTTPError struct {
	StatusCode int
	Code       string
	RetryAfter time.Duration
}

func (err *HTTPError) Error() string {
	return fmt.Sprintf("license service returned HTTP %d (%s)", err.StatusCode, err.Code)
}
func (err *HTTPError) Retryable() bool {
	return err.StatusCode == http.StatusTooManyRequests || err.StatusCode >= http.StatusInternalServerError
}

func NewClient(rawBaseURL string, httpClient HTTPClient) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("invalid WAF report client configuration")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

func (client *Client) Report(ctx context.Context, snapshot Snapshot, privateKey ed25519.PrivateKey) error {
	if client == nil || client.baseURL == nil || client.http == nil || snapshot.InstallationID == uuid.Nil || snapshot.Sequence == 0 ||
		snapshot.RequestID == "" || snapshot.ObservedAt.IsZero() || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid WAF report request")
	}
	policies, digest, err := canonicalPolicies(snapshot.Policies)
	if err != nil || digest != snapshot.PoliciesDigest {
		return errors.New("invalid WAF report snapshot")
	}
	proof := ed25519.Sign(privateKey, proofMessage(snapshot, digest))
	signature := base64.RawURLEncoding.EncodeToString(proof)
	body, err := json.Marshal(struct {
		Schema         string            `json:"schema"`
		InstallationID uuid.UUID         `json:"installation_id"`
		Sequence       uint64            `json:"sequence"`
		ObservedAt     int64             `json:"observed_at"`
		Policies       []json.RawMessage `json:"policies"`
		RequestID      string            `json:"request_id"`
		Signature      string            `json:"signature"`
	}{Schema: Schema, InstallationID: snapshot.InstallationID, Sequence: snapshot.Sequence, ObservedAt: snapshot.ObservedAt.UTC().Unix(), Policies: policies,
		RequestID: snapshot.RequestID, Signature: signature})
	if err != nil {
		return err
	}
	target := *client.baseURL
	target.Path += "/installation/v1/waf-rule-reports"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", snapshot.RequestID)
	request.Header.Set("X-Request-ID", snapshot.RequestID)
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return decodeHTTPError(response)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxResponseBytes {
		return errors.New("invalid WAF report response")
	}
	var result struct {
		Schema         string            `json:"schema"`
		ID             uuid.UUID         `json:"id"`
		InstallationID uuid.UUID         `json:"installation_id"`
		CustomerID     uuid.UUID         `json:"customer_id"`
		LicenseID      uuid.UUID         `json:"license_id"`
		Sequence       uint64            `json:"sequence"`
		ObservedAt     time.Time         `json:"observed_at"`
		ReceivedAt     time.Time         `json:"received_at"`
		Policies       []json.RawMessage `json:"policies"`
		RequestID      string            `json:"request_id"`
		Signature      string            `json:"signature"`
		PoliciesDigest string            `json:"policies_digest"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Schema != Schema ||
		result.ID == uuid.Nil || result.CustomerID == uuid.Nil || result.LicenseID == uuid.Nil || result.ReceivedAt.IsZero() ||
		result.InstallationID != snapshot.InstallationID || result.Sequence != snapshot.Sequence || result.RequestID != snapshot.RequestID ||
		!result.ObservedAt.Equal(time.Unix(snapshot.ObservedAt.Unix(), 0)) || result.Signature != signature ||
		result.PoliciesDigest != hex.EncodeToString(digest[:]) || result.Policies == nil {
		return errors.New("invalid WAF report response")
	}
	_, returnedDigest, err := canonicalPolicies(result.Policies)
	if err != nil || returnedDigest != digest {
		return errors.New("invalid WAF report response")
	}
	return nil
}

func proofMessage(snapshot Snapshot, digest [32]byte) []byte {
	return digestFields("cdnca-waf-custom-rule-report-proof/v1", snapshot.RequestID, snapshot.InstallationID.String(), Schema,
		strconv.FormatUint(snapshot.Sequence, 10), strconv.FormatInt(snapshot.ObservedAt.UTC().Unix(), 10), hex.EncodeToString(digest[:]))
}

func digestFields(values ...string) []byte {
	hash := sha256.New()
	var size [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hash.Sum(nil)
}

func decodeHTTPError(response *http.Response) error {
	var payload struct {
		Code string `json:"code"`
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if readErr == nil && len(encoded) <= 16*1024 {
		_ = json.Unmarshal(encoded, &payload)
	}
	return &HTTPError{StatusCode: response.StatusCode, Code: payload.Code, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())}
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
