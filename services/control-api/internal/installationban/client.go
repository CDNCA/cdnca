// Package installationban is control-api's side of the installation ban
// (ADR 0014 §5): it fetches the installation state from the license service,
// verifies and keeps the signed BanNotice and ServiceTicket (last known good,
// revision never goes back), derives the installation lock and forwards the
// exact document bytes to every node.
package installationban

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
	"github.com/google/uuid"
)

var (
	ErrInvalidConfiguration = errors.New("installation ban: invalid configuration")
	ErrInvalidResponse      = errors.New("installation ban: invalid license service response")
)

// HTTPError is a non-200 answer of the state endpoint.
type HTTPError struct {
	StatusCode int
	Code       string
}

func (err *HTTPError) Error() string {
	return fmt.Sprintf("installation state: license service returned HTTP %d %s", err.StatusCode, err.Code)
}

// Retryable: the license service or the network may answer next round.
func (err *HTTPError) Retryable() bool {
	return err.StatusCode == http.StatusTooManyRequests || err.StatusCode >= 500
}

// Documents is one fetched state: raw signed bytes (nil when absent).
type Documents struct {
	Notice []byte
	Ticket []byte
}

// Fetcher fetches the installation state.
type Fetcher interface {
	Fetch(ctx context.Context, now time.Time) (Documents, error)
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client calls contract.StatePath with the installation key's fetch proof.
type Client struct {
	target         string
	http           HTTPDoer
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
}

func NewClient(baseURL string, installationID uuid.UUID, privateKey ed25519.PrivateKey, doer HTTPDoer) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		installationID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidConfiguration
	}
	if doer == nil {
		doer = &http.Client{Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + contract.StatePath
	return &Client{target: parsed.String(), http: doer, installationID: installationID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...)}, nil
}

func (client *Client) Fetch(ctx context.Context, now time.Time) (Documents, error) {
	proof, err := contract.SignStateFetchProof(contract.StateFetchProof{
		InstallationID: client.installationID.String(), RequestedAt: now.UTC().Unix(),
		RequestID: fmt.Sprintf("control-installation-state-%s-%d", client.installationID, now.UTC().Unix()),
	}, client.privateKey)
	if err != nil {
		return Documents{}, ErrInvalidConfiguration
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.target, nil)
	if err != nil {
		return Documents{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set(contract.HeaderRequestID, proof.RequestID)
	request.Header.Set(contract.HeaderInstallationID, proof.InstallationID)
	request.Header.Set(contract.HeaderRequestedAt, strconv.FormatInt(proof.RequestedAt, 10))
	request.Header.Set(contract.HeaderProof, proof.Signature)
	response, err := client.http.Do(request)
	if err != nil {
		return Documents{}, fmt.Errorf("fetch installation state: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4*contract.MaxDocumentBytes+1))
	if err != nil {
		return Documents{}, fmt.Errorf("read installation state: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		// The license service answers {"code": …}; {"error": {"code": …}} is accepted too.
		var payload struct {
			Code  string `json:"code"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &payload)
		code := payload.Code
		if code == "" {
			code = payload.Error.Code
		}
		return Documents{}, &HTTPError{StatusCode: response.StatusCode, Code: code}
	}
	state, notice, ticket, err := contract.DecodeStateResponse(body)
	if err != nil || state.InstallationID != client.installationID.String() {
		return Documents{}, ErrInvalidResponse
	}
	return Documents{Notice: notice, Ticket: ticket}, nil
}
