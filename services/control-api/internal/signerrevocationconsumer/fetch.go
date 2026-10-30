package signerrevocationconsumer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocation"
	"github.com/google/uuid"
)

const (
	CheckpointPath      = "/installation/v2/signer-revocation-checkpoints/current"
	CheckpointMediaType = "application/vnd.cdnca.signer-revocation-checkpoint.v2+json"
	fetchProofDomain    = "cdnca.signer-revocation-checkpoint-fetch-proof/v2"
	maxClientTimeout    = 30 * time.Second

	ReasonNetworkOutage   = signerrevocation.ReasonCheckpointNetworkOutage
	ReasonServerOutage    = signerrevocation.ReasonCheckpointServerOutage
	ReasonRateLimited     = signerrevocation.ReasonCheckpointRateLimited
	ReasonNotModified     = signerrevocation.ReasonCheckpointNotModified
	ReasonInvalidResponse = signerrevocation.ReasonCheckpointInvalidResponse
)

var (
	ErrInvalidConfiguration = errors.New("invalid signer checkpoint client configuration")
	ErrInvalidKnownState    = errors.New("invalid known signer checkpoint state")
	ErrInvalidResponse      = errors.New("invalid signer checkpoint response")
	ErrRedirectRejected     = errors.New("signer checkpoint redirect rejected")
)

type KnownCheckpoint struct {
	Revision uint64
	SHA256   string
	ETag     string
}

type FetchResult struct {
	Body        []byte
	ETag        string
	NotModified bool
	OperationID uuid.UUID
	ObservedAt  time.Time
}

type FetchError struct {
	Reason      string
	OperationID uuid.UUID
	ObservedAt  time.Time
	Err         error
}

func (failure *FetchError) Error() string {
	if failure == nil || failure.Err == nil {
		return "signer checkpoint fetch failed"
	}
	return failure.Err.Error()
}

func (failure *FetchError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Err
}

type ClientConfig struct {
	BaseURL        string
	TLSConfig      *tls.Config
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	Timeout        time.Duration
	Now            func() time.Time
	NewOperationID func() uuid.UUID
}

type Client struct {
	endpoint       *url.URL
	http           *http.Client
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	now            func() time.Time
	newOperationID func() uuid.UUID
}

func NewClient(config ClientConfig) (*Client, error) {
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.Path != "" || baseURL.RawPath != "" || baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" ||
		baseURL.Opaque != "" || config.InstallationID == uuid.Nil || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		config.Timeout <= 0 || config.Timeout > maxClientTimeout {
		return nil, ErrInvalidConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewOperationID == nil {
		config.NewOperationID = uuid.New
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.TLSConfig != nil {
		if config.TLSConfig.InsecureSkipVerify {
			return nil, ErrInvalidConfiguration
		}
		tlsConfig = config.TLSConfig.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	endpoint := *baseURL
	endpoint.Path = CheckpointPath
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: config.Timeout, ResponseHeaderTimeout: config.Timeout,
	}
	httpClient := &http.Client{Transport: transport, Timeout: config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirectRejected }}
	return &Client{endpoint: &endpoint, http: httpClient, installationID: config.InstallationID,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...), now: config.Now,
		newOperationID: config.NewOperationID}, nil
}

func (client *Client) Fetch(ctx context.Context, known KnownCheckpoint) (FetchResult, error) {
	if client == nil || client.endpoint == nil || client.http == nil || !validKnownCheckpoint(known) {
		return FetchResult{}, ErrInvalidKnownState
	}
	operationID := client.newOperationID()
	requestedAt := client.now().UTC().Truncate(time.Second)
	if operationID == uuid.Nil || requestedAt.IsZero() {
		return FetchResult{}, ErrInvalidConfiguration
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint.String(), nil)
	if err != nil {
		return FetchResult{}, err
	}
	request.Header.Set("Accept", CheckpointMediaType)
	request.Header.Set("X-Request-ID", operationID.String())
	request.Header.Set("X-CDNCA-Installation-ID", client.installationID.String())
	request.Header.Set("X-CDNCA-Requested-At", strconv.FormatInt(requestedAt.Unix(), 10))
	request.Header.Set("X-CDNCA-Known-Checkpoint-Revision", strconv.FormatUint(known.Revision, 10))
	request.Header.Set("X-CDNCA-Known-Checkpoint-SHA256", known.SHA256)
	if known.ETag != "" {
		request.Header.Set("If-None-Match", known.ETag)
	}
	proof := ed25519.Sign(client.privateKey, fetchProofMessage(operationID, client.installationID, requestedAt, known))
	request.Header.Set("X-CDNCA-Proof", base64.RawURLEncoding.EncodeToString(proof))

	response, err := client.http.Do(request)
	if err != nil {
		reason := ReasonNetworkOutage
		if errors.Is(err, ErrRedirectRejected) {
			reason = ReasonInvalidResponse
		}
		return FetchResult{}, &FetchError{Reason: reason, OperationID: operationID,
			ObservedAt: requestedAt, Err: fmt.Errorf("fetch signer checkpoint: %w", err)}
	}
	defer response.Body.Close()
	result := FetchResult{OperationID: operationID, ObservedAt: requestedAt}
	switch {
	case response.StatusCode == http.StatusNotModified:
		if known.Revision == 0 || known.ETag == "" || response.Header.Get("ETag") != known.ETag ||
			response.ContentLength > 0 || len(response.TransferEncoding) != 0 || !emptyResponseBody(response.Body) {
			return FetchResult{}, fetchResponseError(operationID, requestedAt)
		}
		result.NotModified, result.ETag = true, known.ETag
		return result, nil
	case response.StatusCode == http.StatusTooManyRequests:
		return FetchResult{}, &FetchError{Reason: ReasonRateLimited, OperationID: operationID,
			ObservedAt: requestedAt, Err: fmt.Errorf("fetch signer checkpoint: HTTP %d", response.StatusCode)}
	case response.StatusCode >= 500 && response.StatusCode <= 599:
		return FetchResult{}, &FetchError{Reason: ReasonServerOutage, OperationID: operationID,
			ObservedAt: requestedAt, Err: fmt.Errorf("fetch signer checkpoint: HTTP %d", response.StatusCode)}
	case response.StatusCode != http.StatusOK:
		return FetchResult{}, fetchResponseError(operationID, requestedAt)
	}
	if response.Header.Get("Content-Type") != CheckpointMediaType || response.ContentLength <= 0 ||
		response.ContentLength > signercheckpoint.MaxCheckpointBytes || len(response.TransferEncoding) != 0 {
		return FetchResult{}, fetchResponseError(operationID, requestedAt)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, signercheckpoint.MaxCheckpointBytes+1))
	if err != nil || len(body) == 0 || len(body) > signercheckpoint.MaxCheckpointBytes ||
		!validCheckpointETag(response.Header.Get("ETag"), body) {
		return FetchResult{}, fetchResponseError(operationID, requestedAt)
	}
	result.Body, result.ETag = body, response.Header.Get("ETag")
	return result, nil
}

func fetchProofMessage(operationID, installationID uuid.UUID, requestedAt time.Time, known KnownCheckpoint) []byte {
	fields := []string{
		fetchProofDomain, http.MethodGet, CheckpointPath, operationID.String(), installationID.String(),
		strconv.FormatInt(requestedAt.Unix(), 10), strconv.FormatUint(known.Revision, 10), known.SHA256, known.ETag,
	}
	hash := sha256.New()
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = io.WriteString(hash, field)
	}
	return hash.Sum(nil)
}

func validKnownCheckpoint(known KnownCheckpoint) bool {
	if known.Revision == 0 {
		return known.SHA256 == "" && known.ETag == ""
	}
	return validDigest(known.SHA256) && (known.ETag == "" || validStrongETagShape(known.ETag))
}

func validDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validStrongETagShape(value string) bool {
	return len(value) == 45 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) && validDigest(value[1:44])
}

func validCheckpointETag(etag string, body []byte) bool {
	digest := sha256.Sum256(body)
	return etag == `"`+base64.RawURLEncoding.EncodeToString(digest[:])+`"`
}

func emptyResponseBody(body io.Reader) bool {
	encoded, err := io.ReadAll(io.LimitReader(body, 1))
	return err == nil && len(encoded) == 0
}

func fetchResponseError(operationID uuid.UUID, observedAt time.Time) error {
	return &FetchError{Reason: ReasonInvalidResponse, OperationID: operationID,
		ObservedAt: observedAt, Err: ErrInvalidResponse}
}
