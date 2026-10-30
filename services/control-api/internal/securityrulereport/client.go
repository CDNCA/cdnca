package securityrulereport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

const maxResponseBytes = 2 << 20

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
}

func (err *HTTPError) Error() string {
	return fmt.Sprintf("license service returned HTTP %d (%s)", err.StatusCode, err.Code)
}

func NewClient(rawBaseURL string, httpClient HTTPClient) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("invalid security custom rule report client configuration")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

// Request builds the signed upload body (exported for golden/contract tests).
func Request(snapshot Snapshot, privateKey ed25519.PrivateKey) (rulecatalog.ReportRequest, error) {
	canonical, digest, err := rulecatalog.CanonicalReport(snapshot.Report)
	if err != nil || digest != snapshot.Digest || snapshot.Sequence == 0 || snapshot.RequestID == "" ||
		snapshot.ObservedAt.IsZero() || len(privateKey) != ed25519.PrivateKeySize {
		return rulecatalog.ReportRequest{}, errors.New("invalid security custom rule report snapshot")
	}
	request := rulecatalog.ReportRequest{Schema: rulecatalog.ReportSchema, InstallationID: snapshot.InstallationID.String(),
		Sequence: snapshot.Sequence, ObservedAt: snapshot.ObservedAt.UTC().Unix(), Report: canonical, RequestID: snapshot.RequestID}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, rulecatalog.ReportProofMessage(request, digest)))
	return request, nil
}

func (client *Client) Report(ctx context.Context, snapshot Snapshot, privateKey ed25519.PrivateKey) error {
	if client == nil || client.baseURL == nil || client.http == nil {
		return errors.New("security custom rule report client is not configured")
	}
	request, err := Request(snapshot, privateKey)
	if err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	target := *client.baseURL
	target.Path += rulecatalog.ReportPath
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Idempotency-Key", snapshot.RequestID)
	httpRequest.Header.Set("X-Request-ID", snapshot.RequestID)
	response, err := client.http.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(encoded) > maxResponseBytes {
		return errors.New("invalid security custom rule report response")
	}
	if response.StatusCode != http.StatusCreated {
		var payload struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(encoded, &payload)
		return &HTTPError{StatusCode: response.StatusCode, Code: payload.Code}
	}
	var result struct {
		Schema         string `json:"schema"`
		InstallationID string `json:"installation_id"`
		Sequence       uint64 `json:"sequence"`
		RequestID      string `json:"request_id"`
		Signature      string `json:"signature"`
		ReportDigest   string `json:"report_digest"`
	}
	if json.Unmarshal(encoded, &result) != nil || result.Schema != rulecatalog.ReportSchema ||
		result.InstallationID != request.InstallationID || result.Sequence != request.Sequence ||
		result.RequestID != request.RequestID || result.Signature != request.Signature ||
		result.ReportDigest != hex.EncodeToString(snapshot.Digest[:]) {
		return errors.New("security custom rule report receipt does not match the upload")
	}
	return nil
}
