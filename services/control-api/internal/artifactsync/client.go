package artifactsync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
)

const maxResolveResponseBytes = artifactcatalog.MaxSignedBytes + 64<<10

var ErrInvalidResponse = errors.New("invalid artifact catalog response")

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// ServiceError is a non-200 response from the license service.
type ServiceError struct {
	StatusCode int
	Code       string
}

func (err *ServiceError) Error() string {
	return fmt.Sprintf("artifact catalog service returned HTTP %d (%s)", err.StatusCode, err.Code)
}

// Client speaks the installation-facing artifact catalog protocol
// (artifact-catalog:resolve, artifacts:fetch) with the installation key.
type Client struct {
	baseURL *url.URL
	http    HTTPClient
}

func NewClient(rawBaseURL string, httpClient HTTPClient) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("invalid artifact catalog client configuration")
	}
	if httpClient == nil {
		// The IP library can be large: the timeout bounds one whole fetch.
		httpClient = &http.Client{Timeout: 5 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

func (client *Client) Resolve(ctx context.Context, installationID uuid.UUID, controlVersion string, head *artifactcatalog.Head,
	privateKey ed25519.PrivateKey, now time.Time) (artifactcatalog.ResolveResponse, error) {
	request := artifactcatalog.ResolveRequest{Schema: artifactcatalog.ResolveRequestSchema,
		RequestID: "control-artifact-catalog-" + uuid.NewString(), InstallationID: installationID.String(),
		RequestedAt: now.UTC().Unix(), ControlVersion: controlVersion}
	if head != nil {
		request.KnownDeliveryID, request.KnownScopeRevision, request.KnownCatalogSHA256 = head.DeliveryID, head.ScopeRevision, head.CatalogSHA256
	}
	request.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, artifactcatalog.ResolveProofMessage(request)))
	encoded, mediaType, err := client.post(ctx, artifactcatalog.ResolvePath, request.RequestID, request, maxResolveResponseBytes)
	if err != nil {
		return artifactcatalog.ResolveResponse{}, err
	}
	var wire struct {
		Schema         string          `json:"schema"`
		RequestID      string          `json:"request_id"`
		InstallationID string          `json:"installation_id"`
		ResolvedAt     int64           `json:"resolved_at"`
		NotModified    bool            `json:"not_modified"`
		Delivery       json.RawMessage `json:"delivery"`
	}
	if mediaType != "application/json" || rulecatalog.RejectDuplicateKeys(encoded) != nil || decodeStrict(encoded, &wire) != nil ||
		wire.Schema != artifactcatalog.ResolveResponseSchema || wire.RequestID != request.RequestID ||
		wire.InstallationID != request.InstallationID || wire.ResolvedAt < 1 {
		return artifactcatalog.ResolveResponse{}, ErrInvalidResponse
	}
	hasDelivery := len(wire.Delivery) > 0 && string(wire.Delivery) != "null"
	if wire.NotModified == hasDelivery {
		return artifactcatalog.ResolveResponse{}, ErrInvalidResponse
	}
	response := artifactcatalog.ResolveResponse{Schema: wire.Schema, RequestID: wire.RequestID, InstallationID: wire.InstallationID,
		ResolvedAt: wire.ResolvedAt, NotModified: wire.NotModified}
	if hasDelivery {
		signed, err := artifactcatalog.Decode(wire.Delivery)
		if err != nil {
			return artifactcatalog.ResolveResponse{}, ErrInvalidResponse
		}
		response.Delivery = &signed
	}
	return response, nil
}

// Fetch returns the bytes of entry; at most entry.Size bytes are read. The
// caller checks them against the entry.
func (client *Client) Fetch(ctx context.Context, installationID uuid.UUID, entry artifactcatalog.Entry,
	privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	request := artifactcatalog.FetchRequest{Schema: artifactcatalog.FetchRequestSchema,
		RequestID: "control-artifact-fetch-" + uuid.NewString(), InstallationID: installationID.String(),
		RequestedAt: now.UTC().Unix(), ArtifactID: entry.ArtifactID, Revision: entry.Revision, SHA256: entry.SHA256}
	request.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, artifactcatalog.FetchProofMessage(request)))
	content, mediaType, err := client.post(ctx, artifactcatalog.FetchPath, request.RequestID, request, entry.Size)
	if err != nil {
		return nil, err
	}
	if mediaType != artifactcatalog.FetchMediaType {
		return nil, ErrInvalidResponse
	}
	return content, nil
}

func (client *Client) post(ctx context.Context, path, requestID string, body any, limit int64) ([]byte, string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}
	target := *client.baseURL
	target.Path += path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.http.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("send artifact catalog request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		encoded, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		var wire struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(encoded, &wire)
		return nil, "", &ServiceError{StatusCode: response.StatusCode, Code: wire.Code}
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, "", fmt.Errorf("read artifact catalog response: %w", err)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || int64(len(encoded)) > limit {
		return nil, "", ErrInvalidResponse
	}
	return encoded, mediaType, nil
}

func decodeStrict(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidResponse
	}
	return nil
}

// RegisterEncryptionKey registers the installation X25519 encryption key
// (PA-14) with a proof of the identity key; registering the same key again
// changes nothing on the license service.
func (client *Client) RegisterEncryptionKey(ctx context.Context, installationID uuid.UUID, publicKey []byte,
	privateKey ed25519.PrivateKey, now time.Time) (artifactcatalog.RegisterEncryptionKeyResponse, error) {
	request := artifactcatalog.RegisterEncryptionKeyRequest{Schema: artifactcatalog.RegisterEncryptionKeySchema,
		RequestID: "control-encryption-key-" + uuid.NewString(), InstallationID: installationID.String(),
		RequestedAt: now.UTC().Unix(), PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}
	request.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey,
		artifactcatalog.RegisterEncryptionKeyProofMessage(request)))
	encoded, mediaType, err := client.post(ctx, artifactcatalog.RegisterEncryptionKeyPath, request.RequestID, request, 64<<10)
	if err != nil {
		return artifactcatalog.RegisterEncryptionKeyResponse{}, err
	}
	var response artifactcatalog.RegisterEncryptionKeyResponse
	if mediaType != "application/json" || decodeStrict(encoded, &response) != nil ||
		response.InstallationID != request.InstallationID {
		return artifactcatalog.RegisterEncryptionKeyResponse{}, ErrInvalidResponse
	}
	return response, nil
}
