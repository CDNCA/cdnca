package entitlementsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

const maxResponseBytes = 1 << 20

var (
	ErrInvalidConfiguration = errors.New("invalid entitlement sync configuration")
	ErrInvalidResponse      = errors.New("invalid license service response")
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	baseURL *url.URL
	http    HTTPClient
}

type operation struct {
	requestID string
	path      string
	body      []byte
}

type activationRequest struct {
	InstallationID uuid.UUID         `json:"installation_id"`
	Name           string            `json:"name"`
	ActivationCode string            `json:"activation_code"`
	PublicKey      ed25519.PublicKey `json:"-"`
	// EncryptionPublicKey is the optional X25519 installation encryption key
	// (PA-14), proven together with the activation.
	EncryptionPublicKey []byte `json:"-"`
	Proof               []byte `json:"-"`
	RequestID           string `json:"-"`
}

type leaseResponse struct {
	LeaseID     uuid.UUID               `json:"lease_id"`
	SignedLease entitlement.SignedLease `json:"signed_lease"`
}

type HTTPError struct {
	StatusCode int
	Code       string
	RetryAfter time.Duration
}

func (err *HTTPError) Error() string {
	if err.Code == "" {
		return fmt.Sprintf("license service returned HTTP %d", err.StatusCode)
	}
	return fmt.Sprintf("license service returned HTTP %d (%s)", err.StatusCode, err.Code)
}

func (err *HTTPError) Retryable() bool {
	return err.StatusCode == http.StatusTooManyRequests || err.StatusCode >= http.StatusInternalServerError
}

func NewClient(rawBaseURL string, httpClient HTTPClient) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, ErrInvalidConfiguration
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

func prepareActivation(
	installationID uuid.UUID,
	name string,
	activationCode string,
	privateKey ed25519.PrivateKey,
	encryptionPublicKey []byte,
) (operation, error) {
	name = strings.TrimSpace(name)
	credential, err := base64.RawURLEncoding.DecodeString(activationCode)
	if installationID == uuid.Nil || name == "" || utf8.RuneCountInString(name) > 200 || err != nil || len(credential) != 32 ||
		len(privateKey) != ed25519.PrivateKeySize {
		return operation{}, ErrInvalidConfiguration
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return operation{}, ErrInvalidConfiguration
	}
	identity := sha256.New()
	_, _ = identity.Write([]byte(installationID.String()))
	_, _ = identity.Write([]byte{0})
	_, _ = identity.Write([]byte(name))
	_, _ = identity.Write([]byte{0})
	_, _ = identity.Write(publicKey)
	_, _ = identity.Write([]byte{0})
	credentialHash := sha256.Sum256([]byte(activationCode))
	_, _ = identity.Write(credentialHash[:])
	requestID := "control-activate-" + base64.RawURLEncoding.EncodeToString(identity.Sum(nil))
	request := activationRequest{
		InstallationID:      installationID,
		Name:                name,
		ActivationCode:      activationCode,
		PublicKey:           publicKey,
		RequestID:           requestID,
		EncryptionPublicKey: encryptionPublicKey,
	}
	request.Proof = ed25519.Sign(privateKey, activationProofMessage(request))
	body, err := json.Marshal(struct {
		InstallationID      uuid.UUID `json:"installation_id"`
		Name                string    `json:"name"`
		ActivationCode      string    `json:"activation_code"`
		PublicKey           string    `json:"public_key"`
		EncryptionPublicKey string    `json:"encryption_public_key,omitempty"`
		Proof               string    `json:"proof"`
	}{
		InstallationID:      installationID,
		Name:                name,
		ActivationCode:      activationCode,
		PublicKey:           base64.RawURLEncoding.EncodeToString(publicKey),
		EncryptionPublicKey: base64.RawURLEncoding.EncodeToString(encryptionPublicKey),
		Proof:               base64.RawURLEncoding.EncodeToString(request.Proof),
	})
	if err != nil {
		return operation{}, fmt.Errorf("encode activation request: %w", err)
	}
	return operation{requestID: requestID, path: "/activation/v1/installations:activate", body: body}, nil
}

func prepareRenewal(installationID uuid.UUID, currentSerial uint64, privateKey ed25519.PrivateKey) (operation, error) {
	if installationID == uuid.Nil || currentSerial == 0 || len(privateKey) != ed25519.PrivateKeySize {
		return operation{}, ErrInvalidConfiguration
	}
	requestID := fmt.Sprintf("control-renew-%s-%d", installationID, currentSerial)
	proof := ed25519.Sign(privateKey, renewalProofMessage(installationID, requestID))
	body, err := json.Marshal(struct {
		Proof string `json:"proof"`
	}{Proof: base64.RawURLEncoding.EncodeToString(proof)})
	if err != nil {
		return operation{}, fmt.Errorf("encode renewal request: %w", err)
	}
	return operation{
		requestID: requestID,
		path:      "/activation/v1/installations/" + url.PathEscape(installationID.String()) + "/leases:renew",
		body:      body,
	}, nil
}

func (client *Client) exchange(ctx context.Context, op operation) (entitlement.SignedLease, error) {
	if client == nil || client.baseURL == nil || client.http == nil || op.requestID == "" || len(op.body) == 0 {
		return entitlement.SignedLease{}, ErrInvalidConfiguration
	}
	target := *client.baseURL
	target.Path += op.path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(op.body))
	if err != nil {
		return entitlement.SignedLease{}, fmt.Errorf("create license request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", op.requestID)
	request.Header.Set("X-Request-ID", op.requestID)
	response, err := client.http.Do(request)
	if err != nil {
		return entitlement.SignedLease{}, fmt.Errorf("send license request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return entitlement.SignedLease{}, decodeHTTPError(response)
	}
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) > maxResponseBytes {
		return entitlement.SignedLease{}, ErrInvalidResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var payload leaseResponse
	if err := decoder.Decode(&payload); err != nil || payload.LeaseID == uuid.Nil {
		return entitlement.SignedLease{}, ErrInvalidResponse
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return entitlement.SignedLease{}, ErrInvalidResponse
	}
	return payload.SignedLease, nil
}

func decodeHTTPError(response *http.Response) error {
	limited := io.LimitReader(response.Body, 16*1024)
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(limited).Decode(&payload)
	return &HTTPError{
		StatusCode: response.StatusCode,
		Code:       payload.Code,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
	}
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
	var httpError *HTTPError
	if errors.As(err, &httpError) {
		return httpError.RetryAfter, httpError.Retryable()
	}
	return 0, true
}
