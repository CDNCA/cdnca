package controlplaneupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

const (
	publicationSchema = "cdnca.control-plane-upgrade-publication/v1"
	defaultBundleKey  = "bundle.json"
	publicationKey    = "publication.json"
	defaultStateKey   = "control-state.json"
)

var (
	ErrRevisionConflict    = errors.New("control upgrade publication revision conflict")
	ErrIdempotencyConflict = errors.New("control upgrade publication idempotency conflict")
	ErrSecretConflict      = errors.New("control upgrade Secret compare-and-swap conflict")
	ErrSecretUnavailable   = errors.New("control upgrade Secret unavailable")
	secretNamePattern      = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$`)
)

type PublishRequest struct {
	Bundle           []byte
	ExpectedRevision uint64
	IdempotencyKey   string
	RequestID        string
	ActorUserID      uuid.UUID
	ActorScopeID     uuid.UUID
}

type PublicationReceipt struct {
	Schema              string    `json:"schema"`
	ReceiptID           string    `json:"receipt_id"`
	PlanID              string    `json:"plan_id"`
	BundleSHA256        string    `json:"bundle_sha256"`
	PublicationRevision uint64    `json:"publication_revision"`
	ExpectedRevision    uint64    `json:"expected_revision"`
	ChannelRevision     uint64    `json:"channel_revision"`
	ReleaseSequence     uint64    `json:"release_sequence"`
	InstallationID      string    `json:"installation_id"`
	Component           string    `json:"component"`
	CurrentVersion      string    `json:"current_version"`
	CurrentDigest       string    `json:"current_digest"`
	TargetVersion       string    `json:"target_version"`
	TargetDigest        string    `json:"target_digest"`
	RollbackVersion     string    `json:"rollback_version"`
	RollbackDigest      string    `json:"rollback_digest"`
	ProtocolVersion     int       `json:"protocol_version"`
	IdempotencySHA256   string    `json:"idempotency_sha256"`
	RequestID           string    `json:"request_id"`
	ActorUserID         uuid.UUID `json:"actor_user_id"`
	ActorScopeID        uuid.UUID `json:"actor_scope_id"`
	PublishedAt         int64     `json:"published_at"`
	Replayed            bool      `json:"-"`
}

type SecretDocument struct {
	ResourceVersion string
	Bundle          []byte
	Publication     *PublicationReceipt
	Control         *ControlState
	Data            map[string][]byte
}

type SecretRepository interface {
	Read(context.Context) (SecretDocument, error)
	CompareAndSwap(context.Context, string, SecretDocument) (SecretDocument, error)
}

type PlanPublisherConfig struct {
	InstallationID  string
	Component       string
	CurrentVersion  string
	CurrentDigest   string
	ProtocolVersion int
	Trust           *entitlementguard.TrustStore
	Now             func() time.Time
}

type PlanPublisher struct {
	config     PlanPublisherConfig
	repository SecretRepository
}

func NewPlanPublisher(config PlanPublisherConfig, repository SecretRepository) (*PlanPublisher, error) {
	if _, err := uuid.Parse(config.InstallationID); err != nil || config.Component != "control-api" ||
		config.CurrentVersion == "" || !digestPattern.MatchString(config.CurrentDigest) || config.ProtocolVersion < 1 ||
		config.Trust == nil || config.Now == nil || repository == nil {
		return nil, ErrInvalidConfig
	}
	return &PlanPublisher{config: config, repository: repository}, nil
}

func (publisher *PlanPublisher) Publish(ctx context.Context, request PublishRequest) (PublicationReceipt, error) {
	verified, err := publisher.verify(request)
	if err != nil {
		return PublicationReceipt{}, err
	}
	for attempt := 0; attempt < 5; attempt++ {
		document, err := publisher.repository.Read(ctx)
		if err != nil {
			return PublicationReceipt{}, err
		}
		receipt, replayed, err := publisher.prepare(document.Publication, request, verified)
		if err != nil {
			return PublicationReceipt{}, err
		}
		if replayed {
			return receipt, nil
		}
		document.Bundle = append([]byte(nil), request.Bundle...)
		document.Publication = &receipt
		if _, err := publisher.repository.CompareAndSwap(ctx, document.ResourceVersion, document); err != nil {
			if errors.Is(err, ErrSecretConflict) {
				continue
			}
			return PublicationReceipt{}, err
		}
		return receipt, nil
	}
	return PublicationReceipt{}, ErrSecretConflict
}

type verifiedPublication struct {
	bundle        entitlement.UpgradePlanArtifactBundle
	bundleSHA256  string
	currentDigest string
	targetDigest  string
}

func (publisher *PlanPublisher) verify(request PublishRequest) (verifiedPublication, error) {
	if len(request.Bundle) == 0 || len(request.Bundle) > 1<<20 || request.ActorUserID == uuid.Nil ||
		request.ActorScopeID == uuid.Nil || !validMeta(request.IdempotencyKey, 128) || !validMeta(request.RequestID, 128) {
		return verifiedPublication{}, ErrInvalidPlan
	}
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(request.Bundle)
	if err != nil {
		return verifiedPublication{}, ErrInvalidPlan
	}
	bundle, err := publisher.config.Trust.VerifyUpgradePlanArtifactBundle(request.Bundle,
		entitlement.UpgradePlanArtifactBundleVerifyOptions{Now: publisher.config.Now(),
			ExpectedAudience:       entitlement.UpgradePlanArtifactBundleAudience,
			ExpectedInstallationID: publisher.config.InstallationID, ExpectedPlanID: signed.Bundle.PlanID,
			ExpectedInitialPlanRevision: 1})
	if err != nil {
		return verifiedPublication{}, ErrInvalidPlan
	}
	currentDigest, err := manifestDigest(bundle.Rollback.Manifest.SHA256Digest)
	if err != nil {
		return verifiedPublication{}, ErrInvalidPlan
	}
	targetDigest, err := manifestDigest(bundle.Forward.Manifest.SHA256Digest)
	if err != nil || bundle.Component != publisher.config.Component || bundle.CurrentVersion != publisher.config.CurrentVersion ||
		bundle.ProtocolVersion != publisher.config.ProtocolVersion || bundle.Rollback.Manifest.Version != publisher.config.CurrentVersion ||
		bundle.Version != bundle.Forward.Manifest.Version || currentDigest != publisher.config.CurrentDigest ||
		bundle.Forward.Manifest.ReleaseSequence <= bundle.Rollback.Manifest.ReleaseSequence {
		return verifiedPublication{}, ErrInvalidPlan
	}
	return verifiedPublication{bundle: bundle, bundleSHA256: digestBytes(request.Bundle),
		currentDigest: currentDigest, targetDigest: targetDigest}, nil
}

func (publisher *PlanPublisher) prepare(current *PublicationReceipt, request PublishRequest,
	verified verifiedPublication) (PublicationReceipt, bool, error) {
	idempotencyDigest := digestBytes([]byte(request.IdempotencyKey))
	if current != nil {
		if !validPublication(*current) {
			return PublicationReceipt{}, false, ErrSecretUnavailable
		}
		if current.IdempotencySHA256 == idempotencyDigest {
			if current.BundleSHA256 != verified.bundleSHA256 || current.ExpectedRevision != request.ExpectedRevision {
				return PublicationReceipt{}, false, ErrIdempotencyConflict
			}
			replayed := *current
			replayed.Replayed = true
			return replayed, true, nil
		}
		if current.PublicationRevision != request.ExpectedRevision {
			return PublicationReceipt{}, false, ErrRevisionConflict
		}
		if verified.bundle.ChannelRevision <= current.ChannelRevision ||
			verified.bundle.Forward.Manifest.ReleaseSequence <= current.ReleaseSequence {
			return PublicationReceipt{}, false, ErrRevisionConflict
		}
	} else if request.ExpectedRevision != 0 {
		return PublicationReceipt{}, false, ErrRevisionConflict
	}
	revision := request.ExpectedRevision + 1
	receipt := PublicationReceipt{Schema: publicationSchema,
		ReceiptID: fmt.Sprintf("%s:%d", verified.bundle.PlanID, revision), PlanID: verified.bundle.PlanID,
		BundleSHA256: verified.bundleSHA256, PublicationRevision: revision, ExpectedRevision: request.ExpectedRevision,
		ChannelRevision: verified.bundle.ChannelRevision, ReleaseSequence: verified.bundle.Forward.Manifest.ReleaseSequence,
		InstallationID: verified.bundle.InstallationID, Component: verified.bundle.Component,
		CurrentVersion: verified.bundle.CurrentVersion, CurrentDigest: verified.currentDigest,
		TargetVersion: verified.bundle.Version, TargetDigest: verified.targetDigest,
		RollbackVersion: verified.bundle.Rollback.Manifest.Version, RollbackDigest: verified.currentDigest,
		ProtocolVersion: verified.bundle.ProtocolVersion, IdempotencySHA256: idempotencyDigest,
		RequestID: request.RequestID, ActorUserID: request.ActorUserID, ActorScopeID: request.ActorScopeID,
		PublishedAt: publisher.config.Now().UTC().Unix()}
	return receipt, false, nil
}

func validPublication(receipt PublicationReceipt) bool {
	return receipt.Schema == publicationSchema && receipt.ReceiptID != "" && receipt.PlanID != "" &&
		digestPattern.MatchString(receipt.BundleSHA256) && receipt.PublicationRevision > 0 &&
		receipt.ChannelRevision > 0 && receipt.ReleaseSequence > 0 && receipt.InstallationID != "" &&
		receipt.Component == "control-api" && receipt.CurrentVersion != "" && receipt.TargetVersion != "" &&
		digestPattern.MatchString(receipt.CurrentDigest) && digestPattern.MatchString(receipt.TargetDigest) &&
		digestPattern.MatchString(receipt.RollbackDigest) && receipt.ProtocolVersion > 0 &&
		digestPattern.MatchString(receipt.IdempotencySHA256) && receipt.RequestID != "" &&
		receipt.ActorUserID != uuid.Nil && receipt.ActorScopeID != uuid.Nil && receipt.PublishedAt > 0
}

func manifestDigest(value string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", ErrInvalidPlan
	}
	return hex.EncodeToString(decoded), nil
}

func validMeta(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index, character := range value {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if !alphaNumeric && character != '.' && character != '_' && character != ':' && character != '-' ||
			index == 0 && !alphaNumeric {
			return false
		}
	}
	return true
}

func cloneSecretDocument(document SecretDocument) SecretDocument {
	cloned := document
	cloned.Bundle = append([]byte(nil), document.Bundle...)
	if document.Publication != nil {
		publication := *document.Publication
		cloned.Publication = &publication
	}
	if document.Control != nil {
		control := cloneControlState(*document.Control)
		cloned.Control = &control
	}
	cloned.Data = make(map[string][]byte, len(document.Data))
	for key, value := range document.Data {
		cloned.Data[key] = append([]byte(nil), value...)
	}
	return cloned
}

type KubernetesSecretConfig struct {
	APIServer      string
	Namespace      string
	SecretName     string
	BundleKey      string
	StateKey       string
	TokenFile      string
	CAFile         string
	HTTPClient     *http.Client
	RequestTimeout time.Duration
}

type KubernetesSecretRepository struct {
	config KubernetesSecretConfig
	client *http.Client
}

func NewKubernetesSecretRepository(config KubernetesSecretConfig) (*KubernetesSecretRepository, error) {
	parsed, err := url.Parse(config.APIServer)
	if err != nil || parsed.Host == "" || !secretNamePattern.MatchString(config.Namespace) ||
		!secretNamePattern.MatchString(config.SecretName) {
		return nil, ErrInvalidConfig
	}
	if config.BundleKey == "" {
		config.BundleKey = defaultBundleKey
	}
	if config.StateKey == "" {
		config.StateKey = defaultStateKey
	}
	if !validSecretKey(config.BundleKey) || !validSecretKey(config.StateKey) || config.BundleKey == config.StateKey {
		return nil, ErrInvalidConfig
	}
	client := config.HTTPClient
	if client == nil {
		if parsed.Scheme != "https" || config.TokenFile == "" || config.CAFile == "" {
			return nil, ErrInvalidConfig
		}
		_, tokenErr := readKubernetesToken(config.TokenFile)
		encodedCA, caErr := os.ReadFile(config.CAFile)
		roots := x509.NewCertPool()
		if tokenErr != nil || caErr != nil || !roots.AppendCertsFromPEM(encodedCA) {
			return nil, ErrInvalidConfig
		}
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, ErrInvalidConfig
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 10 * time.Second
	}
	return &KubernetesSecretRepository{config: config, client: client}, nil
}

type kubernetesSecret struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace,omitempty"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Type string            `json:"type,omitempty"`
	Data map[string]string `json:"data"`
}

func (repository *KubernetesSecretRepository) Read(ctx context.Context) (SecretDocument, error) {
	var secret kubernetesSecret
	status, err := repository.request(ctx, http.MethodGet, nil, &secret)
	if err != nil {
		if status == http.StatusNotFound {
			return SecretDocument{}, ErrSecretUnavailable
		}
		return SecretDocument{}, err
	}
	return repository.decode(secret)
}

func (repository *KubernetesSecretRepository) CompareAndSwap(ctx context.Context, expected string,
	document SecretDocument) (SecretDocument, error) {
	if expected == "" || document.ResourceVersion != expected {
		return SecretDocument{}, ErrSecretConflict
	}
	data := make(map[string]string, len(document.Data)+3)
	for key, value := range document.Data {
		data[key] = base64.StdEncoding.EncodeToString(value)
	}
	data[repository.config.BundleKey] = base64.StdEncoding.EncodeToString(document.Bundle)
	publication, err := canonicalJSON(document.Publication)
	if err != nil {
		return SecretDocument{}, err
	}
	data[publicationKey] = base64.StdEncoding.EncodeToString(publication)
	if document.Control != nil {
		state, err := canonicalJSON(document.Control)
		if err != nil {
			return SecretDocument{}, err
		}
		data[repository.config.StateKey] = base64.StdEncoding.EncodeToString(state)
	}
	secret := kubernetesSecret{APIVersion: "v1", Kind: "Secret", Type: "Opaque", Data: data}
	secret.Metadata.Name, secret.Metadata.Namespace, secret.Metadata.ResourceVersion = repository.config.SecretName,
		repository.config.Namespace, expected
	encoded, _ := json.Marshal(secret)
	var updated kubernetesSecret
	status, err := repository.request(ctx, http.MethodPut, encoded, &updated)
	if status == http.StatusConflict {
		return SecretDocument{}, ErrSecretConflict
	}
	if err != nil {
		return SecretDocument{}, err
	}
	return repository.decode(updated)
}

func (repository *KubernetesSecretRepository) decode(secret kubernetesSecret) (SecretDocument, error) {
	if secret.Metadata.Name != repository.config.SecretName || secret.Metadata.ResourceVersion == "" || secret.Data == nil {
		return SecretDocument{}, ErrSecretUnavailable
	}
	document := SecretDocument{ResourceVersion: secret.Metadata.ResourceVersion, Data: make(map[string][]byte)}
	for key, value := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) > 2<<20 {
			return SecretDocument{}, ErrSecretUnavailable
		}
		switch key {
		case repository.config.BundleKey:
			document.Bundle = decoded
		case publicationKey:
			var publication PublicationReceipt
			if decodeCanonicalJSON(decoded, &publication) != nil || !validPublication(publication) {
				return SecretDocument{}, ErrSecretUnavailable
			}
			document.Publication = &publication
		case repository.config.StateKey:
			var state ControlState
			if decodeCanonicalJSON(decoded, &state) != nil || !validControlState(state) {
				return SecretDocument{}, ErrSecretUnavailable
			}
			document.Control = &state
		default:
			document.Data[key] = decoded
		}
	}
	return document, nil
}

func (repository *KubernetesSecretRepository) request(ctx context.Context, method string, body []byte, output any) (int, error) {
	requestContext, cancel := context.WithTimeout(ctx, repository.config.RequestTimeout)
	defer cancel()
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", url.PathEscape(repository.config.Namespace),
		url.PathEscape(repository.config.SecretName))
	request, err := http.NewRequestWithContext(requestContext, method,
		strings.TrimRight(repository.config.APIServer, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
	}
	if repository.config.TokenFile != "" {
		token, err := readKubernetesToken(repository.config.TokenFile)
		if err != nil {
			return 0, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := repository.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 3<<20))
	if err != nil {
		return response.StatusCode, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("kubernetes Secret API status %d", response.StatusCode)
	}
	if output != nil && len(encoded) > 0 {
		if err := json.Unmarshal(encoded, output); err != nil {
			return response.StatusCode, err
		}
	}
	return response.StatusCode, nil
}

func validSecretKey(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func canonicalJSON(value any) ([]byte, error) {
	if value == nil {
		return nil, ErrSecretUnavailable
	}
	return json.Marshal(value)
}

func decodeCanonicalJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrSecretUnavailable
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrSecretUnavailable
	}
	return nil
}

func parseRevision(value string) (uint64, error) {
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, ErrRevisionConflict
	}
	return revision, nil
}
