package pluginruntimecomposition

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginworkloadidentity"
	"github.com/google/uuid"
)

const (
	projectionPath                   = "/installation/v1/plugin-runtime-projections:resolve"
	projectionRequestSchema          = "cdnca.plugin-runtime-projection-request/v1"
	projectionSchema                 = "cdnca.plugin-runtime-projection/v1"
	projectionRequestDomain          = "cdnca-plugin-runtime-projection-request/v1"
	projectionSigningDomain          = "cdnca-plugin-runtime-projection/v1"
	webhookAttemptDomain             = "cdnca-plugin-runtime-webhook-attempt/v1"
	maximumBodyBytes           int64 = 64 << 10
	maximumResponseHeaderBytes int64 = 64 << 10
	maximumTimeout                   = 5 * time.Second
	webhookCapabilityCode            = "webhook.deliver"
)

var (
	ErrInvalidConfiguration = errors.New("invalid plugin runtime composition configuration")
	ErrInvalidInput         = errors.New("invalid plugin runtime composition input")
	ErrDenied               = errors.New("plugin runtime composition denied")
	ErrInvalid              = errors.New("plugin runtime composition response invalid")
	ErrUnavailable          = errors.New("plugin runtime composition unavailable")

	errRedirect = errors.New("plugin runtime projection redirect rejected")

	hexDigestPattern           = regexp.MustCompile(`^[a-f0-9]{64}$`)
	permissionPattern          = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,7}$`)
	eventPattern               = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)
	supportedWebhookEventTypes = map[string]struct{}{
		"io.cdnca.webhook.v1.test":               {},
		"io.cdnca.certificate.v1.expiry_reached": {},
		"io.cdnca.certificate.v1.status_changed": {},
		"io.cdnca.deployment.v1.status_changed":  {},
		"io.cdnca.dns.v1.changed":                {},
		"io.cdnca.dns.v1.deleted":                {},
		"io.cdnca.node.v1.status_changed":        {},
		"io.cdnca.security.v1.incident_detected": {},
		"io.cdnca.site.v1.updated":               {},
		"io.cdnca.usage.v1.threshold_reached":    {},
	}
)

type ProjectionClientConfig struct {
	BaseURL        string
	TLSConfig      *tls.Config
	Credentials    ProjectionCredentialSource
	InstallationID uuid.UUID
	Trust          *entitlementguard.TrustStore
	Now            func() time.Time
	Timeout        time.Duration
	MaxBodyBytes   int64
	// DialContext opens the connection the inner TLS runs over (libs/mtlstunnel
	// tunnel); nil dials directly.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// RuntimeCredential is a single, internally consistent certificate snapshot.
// The private key is copied and cleared by consumers after each request.
type RuntimeCredential struct {
	CertificateID  uuid.UUID
	PrivateKey     ed25519.PrivateKey
	TLSCertificate tls.Certificate
	RootCAs        *x509.CertPool
}

type ProjectionCredential = RuntimeCredential

type ProjectionCredentialSource interface {
	Ensure(context.Context) (RuntimeCredential, error)
}

type ProjectionRequest struct {
	RequestID      string
	InstallationID uuid.UUID
	ConsumerKind   string
	ConsumerID     uuid.UUID
	TargetScopeID  uuid.UUID
	CapabilityKind string
	CapabilityCode string
	RequestedAt    time.Time
}

type Projection struct {
	RequestID           string
	InstallationID      uuid.UUID
	CertificateID       uuid.UUID
	Generation          uint64
	BindingID           uuid.UUID
	BindingRevision     uint64
	AuthorizationID     uuid.UUID
	ServiceIdentityJSON []byte
	ManifestSHA256      string
	VerificationID      uuid.UUID
	AttestationID       uuid.UUID
	AttestationRevision uint64
	ApprovalRevision    uint64
	CapabilityKind      string
	CapabilityCode      string
	IssuedAt            time.Time
	ExpiresAt           time.Time
}

type ProjectionClient struct {
	endpoint       string
	http           *http.Client
	installationID uuid.UUID
	certificateID  uuid.UUID
	privateKey     ed25519.PrivateKey
	trust          *entitlementguard.TrustStore
	now            func() time.Time
	bodyLimit      int64
	credentials    ProjectionCredentialSource
	timeout        time.Duration
	dial           func(context.Context, string, string) (net.Conn, error)
}

type projectionRequestPayload struct {
	Schema         string    `json:"schema"`
	RequestID      string    `json:"request_id"`
	InstallationID uuid.UUID `json:"installation_id"`
	CertificateID  uuid.UUID `json:"certificate_id"`
	ConsumerKind   string    `json:"consumer_kind"`
	ConsumerID     uuid.UUID `json:"consumer_id"`
	TargetScopeID  uuid.UUID `json:"target_scope_id"`
	CapabilityKind string    `json:"capability_kind"`
	CapabilityCode string    `json:"capability_code"`
	RequestedAt    time.Time `json:"requested_at"`
}

type projectionRequestBody struct {
	Schema         string    `json:"schema"`
	RequestID      string    `json:"request_id"`
	InstallationID uuid.UUID `json:"installation_id"`
	CertificateID  uuid.UUID `json:"certificate_id"`
	ConsumerKind   string    `json:"consumer_kind"`
	ConsumerID     uuid.UUID `json:"consumer_id"`
	TargetScopeID  uuid.UUID `json:"target_scope_id"`
	CapabilityKind string    `json:"capability_kind"`
	CapabilityCode string    `json:"capability_code"`
	RequestedAt    time.Time `json:"requested_at"`
	Proof          string    `json:"proof"`
}

type projectionWire struct {
	Schema              string          `json:"schema"`
	RequestID           string          `json:"request_id"`
	InstallationID      uuid.UUID       `json:"installation_id"`
	CertificateID       uuid.UUID       `json:"certificate_id"`
	Generation          uint64          `json:"generation"`
	BindingID           uuid.UUID       `json:"binding_id"`
	BindingRevision     uint64          `json:"binding_revision"`
	AuthorizationID     uuid.UUID       `json:"authorization_id"`
	ServiceIdentity     json.RawMessage `json:"service_identity"`
	ManifestSHA256      string          `json:"manifest_sha256"`
	VerificationID      uuid.UUID       `json:"verification_id"`
	AttestationID       uuid.UUID       `json:"attestation_id"`
	AttestationRevision uint64          `json:"attestation_revision"`
	ApprovalRevision    uint64          `json:"approval_revision"`
	CapabilityKind      string          `json:"capability_kind"`
	CapabilityCode      string          `json:"capability_code"`
	IssuedAt            time.Time       `json:"issued_at"`
	ExpiresAt           time.Time       `json:"expires_at"`
	Algorithm           string          `json:"algorithm"`
	KeyID               string          `json:"key_id"`
	Signature           string          `json:"signature"`
}

type projectionPayload struct {
	Schema              string          `json:"schema"`
	RequestID           string          `json:"request_id"`
	InstallationID      uuid.UUID       `json:"installation_id"`
	CertificateID       uuid.UUID       `json:"certificate_id"`
	Generation          uint64          `json:"generation"`
	BindingID           uuid.UUID       `json:"binding_id"`
	BindingRevision     uint64          `json:"binding_revision"`
	AuthorizationID     uuid.UUID       `json:"authorization_id"`
	ServiceIdentity     json.RawMessage `json:"service_identity"`
	ManifestSHA256      string          `json:"manifest_sha256"`
	VerificationID      uuid.UUID       `json:"verification_id"`
	AttestationID       uuid.UUID       `json:"attestation_id"`
	AttestationRevision uint64          `json:"attestation_revision"`
	ApprovalRevision    uint64          `json:"approval_revision"`
	CapabilityKind      string          `json:"capability_kind"`
	CapabilityCode      string          `json:"capability_code"`
	IssuedAt            time.Time       `json:"issued_at"`
	ExpiresAt           time.Time       `json:"expires_at"`
	Algorithm           string          `json:"algorithm"`
	KeyID               string          `json:"key_id"`
}

func NewProjectionClient(config ProjectionClientConfig) (*ProjectionClient, error) {
	baseURL, err := exactHTTPSOrigin(config.BaseURL)
	if err != nil || config.InstallationID == uuid.Nil || config.Trust == nil || config.Now == nil || config.Now().IsZero() ||
		config.Timeout <= 0 || config.Timeout > maximumTimeout ||
		config.MaxBodyBytes <= 0 || config.MaxBodyBytes > maximumBodyBytes {
		return nil, ErrInvalidConfiguration
	}
	if (config.TLSConfig == nil) == (config.Credentials == nil) {
		return nil, ErrInvalidConfiguration
	}
	var certificateID uuid.UUID
	var privateKey ed25519.PrivateKey
	var client *http.Client
	if config.TLSConfig != nil {
		if config.TLSConfig.InsecureSkipVerify || config.TLSConfig.MinVersion != tls.VersionTLS13 ||
			config.TLSConfig.MaxVersion != 0 && config.TLSConfig.MaxVersion != tls.VersionTLS13 ||
			config.TLSConfig.RootCAs == nil || len(config.TLSConfig.Certificates) != 1 {
			return nil, ErrInvalidConfiguration
		}
		certificateID, privateKey, err = validateClientCertificate(config.TLSConfig.Certificates[0], config.InstallationID, config.Now())
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		client = newProjectionHTTPClient(config.TLSConfig, config.Timeout, config.DialContext)
	}
	return &ProjectionClient{endpoint: baseURL.String() + projectionPath, http: client,
		installationID: config.InstallationID, certificateID: certificateID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...), trust: config.Trust,
		now: config.Now, bodyLimit: config.MaxBodyBytes, credentials: config.Credentials,
		timeout: config.Timeout, dial: config.DialContext}, nil
}

func (client *ProjectionClient) Resolve(ctx context.Context, request ProjectionRequest) (Projection, error) {
	if client == nil || ctx == nil || client.trust == nil || client.now == nil || client.now().IsZero() ||
		!validProjectionRequest(request, client.installationID, client.now()) {
		return Projection{}, ErrInvalidInput
	}
	certificateID, privateKey := client.certificateID, client.privateKey
	httpClient := client.http
	if client.credentials != nil {
		credential, err := client.credentials.Ensure(ctx)
		if err != nil {
			return Projection{}, ErrUnavailable
		}
		defer clearRuntimeCredential(&credential)
		certificateID, privateKey = credential.CertificateID, credential.PrivateKey
		if certificateID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize || credential.RootCAs == nil {
			return Projection{}, ErrInvalidInput
		}
		if _, _, err := validateClientCertificate(credential.TLSCertificate, client.installationID, client.now()); err != nil {
			return Projection{}, ErrInvalidInput
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: credential.RootCAs, Certificates: []tls.Certificate{credential.TLSCertificate}}
		httpClient = newProjectionHTTPClient(tlsConfig, client.timeout, client.dial)
	}
	payload := projectionRequestPayload{Schema: projectionRequestSchema, RequestID: request.RequestID,
		InstallationID: request.InstallationID, CertificateID: certificateID,
		ConsumerKind: request.ConsumerKind, ConsumerID: request.ConsumerID, TargetScopeID: request.TargetScopeID,
		CapabilityKind: request.CapabilityKind, CapabilityCode: request.CapabilityCode, RequestedAt: request.RequestedAt}
	unsigned, err := json.Marshal(payload)
	if err != nil || int64(len(unsigned)) > client.bodyLimit {
		return Projection{}, ErrInvalidInput
	}
	proof := ed25519.Sign(privateKey, lengthPrefixed(projectionRequestDomain, unsigned))
	body, err := json.Marshal(projectionRequestBody{Schema: payload.Schema, RequestID: payload.RequestID,
		InstallationID: payload.InstallationID, CertificateID: payload.CertificateID, ConsumerKind: payload.ConsumerKind,
		ConsumerID: payload.ConsumerID, TargetScopeID: payload.TargetScopeID, CapabilityKind: payload.CapabilityKind,
		CapabilityCode: payload.CapabilityCode, RequestedAt: payload.RequestedAt,
		Proof: base64.RawURLEncoding.EncodeToString(proof)})
	clear(proof)
	if err != nil || int64(len(body)) > client.bodyLimit {
		return Projection{}, ErrInvalidInput
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(body))
	if err != nil {
		return Projection{}, ErrInvalidInput
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return Projection{}, ErrInvalid
		}
		return Projection{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		switch {
		case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
			response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusConflict:
			return Projection{}, ErrDenied
		case response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
			return Projection{}, ErrUnavailable
		default:
			return Projection{}, ErrInvalid
		}
	}
	if contentTypes := response.Header.Values("Content-Type"); len(contentTypes) != 1 || contentTypes[0] != "application/json" ||
		response.Header.Get("Content-Encoding") != "" {
		return Projection{}, ErrInvalid
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, client.bodyLimit+2))
	if readErr != nil {
		return Projection{}, ErrUnavailable
	}
	if len(encoded) < 2 || int64(len(encoded)) > client.bodyLimit+1 || encoded[len(encoded)-1] != '\n' {
		return Projection{}, ErrInvalid
	}
	return client.verifyResponse(encoded[:len(encoded)-1], request, certificateID)
}

func (client *ProjectionClient) verifyResponse(encoded []byte, request ProjectionRequest, certificateID uuid.UUID) (Projection, error) {
	var wire projectionWire
	if json.Unmarshal(encoded, &wire) != nil {
		return Projection{}, ErrInvalid
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) || !validProjectionWire(wire) {
		return Projection{}, ErrInvalid
	}
	if wire.RequestID != request.RequestID || wire.InstallationID != request.InstallationID ||
		wire.CertificateID != certificateID || wire.CapabilityKind != request.CapabilityKind ||
		wire.CapabilityCode != request.CapabilityCode {
		return Projection{}, ErrDenied
	}
	now := client.now().UTC()
	if wire.IssuedAt.Before(request.RequestedAt) || wire.IssuedAt.After(now) || !now.Before(wire.ExpiresAt) ||
		wire.ExpiresAt.Sub(wire.IssuedAt) <= 0 || wire.ExpiresAt.Sub(wire.IssuedAt) > time.Minute {
		return Projection{}, ErrDenied
	}
	signature, err := base64.RawURLEncoding.DecodeString(wire.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != wire.Signature {
		return Projection{}, ErrInvalid
	}
	payload, err := json.Marshal(projectionPayload{Schema: wire.Schema, RequestID: wire.RequestID,
		InstallationID: wire.InstallationID, CertificateID: wire.CertificateID, Generation: wire.Generation,
		BindingID: wire.BindingID, BindingRevision: wire.BindingRevision, AuthorizationID: wire.AuthorizationID,
		ServiceIdentity: wire.ServiceIdentity, ManifestSHA256: wire.ManifestSHA256, VerificationID: wire.VerificationID,
		AttestationID: wire.AttestationID, AttestationRevision: wire.AttestationRevision,
		ApprovalRevision: wire.ApprovalRevision, CapabilityKind: wire.CapabilityKind, CapabilityCode: wire.CapabilityCode,
		IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, Algorithm: wire.Algorithm, KeyID: wire.KeyID})
	if err != nil || client.trust.VerifyDetached(wire.KeyID, lengthPrefixed(projectionSigningDomain, payload),
		signature, wire.IssuedAt, now) != nil {
		return Projection{}, ErrInvalid
	}
	return Projection{RequestID: wire.RequestID, InstallationID: wire.InstallationID,
		CertificateID: wire.CertificateID, Generation: wire.Generation, BindingID: wire.BindingID,
		BindingRevision: wire.BindingRevision, AuthorizationID: wire.AuthorizationID,
		ServiceIdentityJSON: append([]byte(nil), wire.ServiceIdentity...), ManifestSHA256: wire.ManifestSHA256,
		VerificationID: wire.VerificationID, AttestationID: wire.AttestationID,
		AttestationRevision: wire.AttestationRevision, ApprovalRevision: wire.ApprovalRevision,
		CapabilityKind: wire.CapabilityKind, CapabilityCode: wire.CapabilityCode,
		IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt}, nil
}

type ProjectionResolver interface {
	Resolve(context.Context, ProjectionRequest) (Projection, error)
}

type WorkloadAuthorizer interface {
	Authorize(context.Context, pluginworkloadidentity.Request) (pluginworkloadidentity.Authorization, error)
}

type V2Deliverer interface {
	DeliverV2(context.Context, pluginwebhook.QueueItem, uint64, []byte) pluginwebhook.SendResult
}

type WebhookDelivererConfig struct {
	InstallationID uuid.UUID
	Projection     ProjectionResolver
	Authorizer     WorkloadAuthorizer
	Delegate       V2Deliverer
	Now            func() time.Time
}

type WebhookDeliverer struct {
	config WebhookDelivererConfig
}

func NewWebhookDeliverer(config WebhookDelivererConfig) (*WebhookDeliverer, error) {
	if config.InstallationID == uuid.Nil || nilInterface(config.Projection) || nilInterface(config.Authorizer) ||
		nilInterface(config.Delegate) || config.Now == nil || config.Now().IsZero() {
		return nil, ErrInvalidConfiguration
	}
	return &WebhookDeliverer{config: config}, nil
}

func (deliverer *WebhookDeliverer) Deliver(context.Context, pluginwebhook.QueueItem, uint64) pluginwebhook.SendResult {
	return pluginwebhook.SendResult{Code: "invalid_delivery"}
}

func (deliverer *WebhookDeliverer) DeliverV2(ctx context.Context, item pluginwebhook.QueueItem,
	attempt uint64, secret []byte) pluginwebhook.SendResult {
	if !deliverer.validAction(ctx, item, attempt, secret) {
		return authorizationDenied()
	}
	now := deliverer.config.Now().UTC().Truncate(time.Second)
	requestID := webhookAttemptRequestID(item.DeliveryID, attempt)
	request := ProjectionRequest{RequestID: requestID, InstallationID: deliverer.config.InstallationID,
		ConsumerKind: "webhook", ConsumerID: item.SubscriptionID, TargetScopeID: item.TargetScopeID,
		CapabilityKind: "webhook", CapabilityCode: webhookCapabilityCode, RequestedAt: now}
	projection, err := deliverer.config.Projection.Resolve(ctx, request)
	defer clear(projection.ServiceIdentityJSON)
	if err != nil {
		return mapAuthorizationError(err)
	}
	if !projectionMatchesRequest(projection, request) {
		return authorizationDenied()
	}
	pluginID, ok := projectionIdentityBinding(projection.ServiceIdentityJSON, projection.AuthorizationID)
	if !ok {
		return authorizationDenied()
	}
	workloadRequest := pluginworkloadidentity.Request{
		TenantID: item.TenantID, InstallationID: request.InstallationID, InvocationID: item.EventID,
		PluginID: pluginID, CapabilityKind: request.CapabilityKind, CapabilityCode: request.CapabilityCode,
		Action: "plugin.webhook.deliver", ServiceIdentityJSON: projection.ServiceIdentityJSON,
		ManifestSHA256: projection.ManifestSHA256, VerificationID: projection.VerificationID,
		AttestationID: projection.AttestationID, AttestationRevision: projection.AttestationRevision,
		ApprovalRevision: projection.ApprovalRevision, RequestedAt: now,
	}
	authorization, err := deliverer.config.Authorizer.Authorize(ctx, workloadRequest)
	if err != nil {
		if errors.Is(err, pluginworkloadidentity.ErrRateLimited) {
			return authorizationRateLimited(now)
		}
		return mapAuthorizationError(err)
	}
	if !authorization.ValidFor(workloadRequest, now) {
		return authorizationDenied()
	}
	return deliverer.config.Delegate.DeliverV2(ctx, item, attempt, secret)
}

func (deliverer *WebhookDeliverer) validAction(ctx context.Context, item pluginwebhook.QueueItem,
	attempt uint64, secret []byte) bool {
	return deliverer != nil && ctx != nil && attempt > 0 && len(secret) > 0 &&
		deliverer.config.InstallationID != uuid.Nil && deliverer.config.Now != nil &&
		!nilInterface(deliverer.config.Projection) && !nilInterface(deliverer.config.Authorizer) &&
		!nilInterface(deliverer.config.Delegate) &&
		item.Schema == pluginwebhook.QueueSchemaV2 && item.TargetScopeID != uuid.Nil && item.TenantID != uuid.Nil &&
		item.TargetScopeID != item.TenantID && item.SubscriptionID != uuid.Nil && item.SecretVersionID != uuid.Nil &&
		item.DeliveryID != uuid.Nil && item.EventID != uuid.Nil && item.EventID.Version() == 7 &&
		item.EventID.Variant() == uuid.RFC4122 && item.Event.ID == item.EventID.String() &&
		isSupportedWebhookEventType(item.Event.Type)
}

func isSupportedWebhookEventType(eventType string) bool {
	if !eventPattern.MatchString(eventType) {
		return false
	}
	_, ok := supportedWebhookEventTypes[eventType]
	return ok
}

func projectionMatchesRequest(projection Projection, request ProjectionRequest) bool {
	return projection.RequestID == request.RequestID && projection.InstallationID == request.InstallationID &&
		projection.CertificateID != uuid.Nil && projection.Generation > 0 && projection.BindingID != uuid.Nil &&
		projection.BindingRevision > 0 && projection.AuthorizationID != uuid.Nil && len(projection.ServiceIdentityJSON) > 0 &&
		hexDigestPattern.MatchString(projection.ManifestSHA256) && projection.VerificationID != uuid.Nil &&
		projection.AttestationID != uuid.Nil && projection.AttestationRevision > 0 && projection.ApprovalRevision > 0 &&
		projection.CapabilityKind == request.CapabilityKind && projection.CapabilityCode == request.CapabilityCode &&
		projection.IssuedAt.Equal(projection.IssuedAt.UTC().Truncate(time.Second)) &&
		projection.ExpiresAt.After(projection.IssuedAt) && !projection.IssuedAt.Before(request.RequestedAt) &&
		request.RequestedAt.Before(projection.ExpiresAt)
}

func projectionIdentityBinding(identity []byte, authorizationID uuid.UUID) (string, bool) {
	var binding struct {
		AuthorizationID uuid.UUID `json:"authorization_id"`
		PluginID        string    `json:"plugin_id"`
	}
	if json.Unmarshal(identity, &binding) != nil || binding.AuthorizationID != authorizationID || binding.PluginID == "" {
		return "", false
	}
	return binding.PluginID, true
}

func mapAuthorizationError(err error) pluginwebhook.SendResult {
	if errors.Is(err, ErrUnavailable) || errors.Is(err, pluginworkloadidentity.ErrUnavailable) {
		return authorizationUnavailable()
	}
	return authorizationDenied()
}

func authorizationDenied() pluginwebhook.SendResult {
	return pluginwebhook.SendResult{Code: "runtime_authorization_denied"}
}

func authorizationUnavailable() pluginwebhook.SendResult {
	return pluginwebhook.SendResult{Code: "runtime_authorization_unavailable", Retryable: true}
}

func authorizationRateLimited(now time.Time) pluginwebhook.SendResult {
	retryAfter := now.UTC().Truncate(time.Minute).Add(time.Minute).Sub(now.UTC())
	return pluginwebhook.SendResult{Code: "runtime_rate_limited", Retryable: true, RetryAfter: retryAfter}
}

func webhookAttemptRequestID(deliveryID uuid.UUID, attempt uint64) string {
	digest := sha256.Sum256(lengthPrefixed(webhookAttemptDomain, deliveryID[:], []byte(strconv.FormatUint(attempt, 10))))
	return hex.EncodeToString(digest[:])
}

func validProjectionRequest(request ProjectionRequest, installationID uuid.UUID, now time.Time) bool {
	return request.InstallationID == installationID && installationID != uuid.Nil && validVisibleASCII(request.RequestID) &&
		(request.ConsumerKind == "event" || request.ConsumerKind == "webhook") && request.ConsumerID != uuid.Nil &&
		request.TargetScopeID != uuid.Nil && validCapability(request.CapabilityKind, request.CapabilityCode) &&
		request.RequestedAt.Equal(request.RequestedAt.UTC().Truncate(time.Second)) &&
		!request.RequestedAt.Before(now.UTC().Add(-5*time.Minute)) && !request.RequestedAt.After(now.UTC().Add(time.Minute))
}

func validProjectionWire(wire projectionWire) bool {
	return wire.Schema == projectionSchema && validVisibleASCII(wire.RequestID) && wire.InstallationID != uuid.Nil &&
		wire.CertificateID != uuid.Nil && wire.Generation > 0 && wire.BindingID != uuid.Nil && wire.BindingRevision > 0 &&
		wire.AuthorizationID != uuid.Nil && len(wire.ServiceIdentity) > 0 && int64(len(wire.ServiceIdentity)) <= maximumBodyBytes &&
		hexDigestPattern.MatchString(wire.ManifestSHA256) && wire.VerificationID != uuid.Nil && wire.AttestationID != uuid.Nil &&
		wire.AttestationRevision > 0 && wire.ApprovalRevision > 0 && validCapability(wire.CapabilityKind, wire.CapabilityCode) &&
		wire.IssuedAt.Equal(wire.IssuedAt.UTC().Truncate(time.Second)) &&
		wire.ExpiresAt.Equal(wire.ExpiresAt.UTC().Truncate(time.Second)) && wire.Algorithm == "Ed25519" &&
		validVisibleASCII(wire.KeyID)
}

func validCapability(kind, code string) bool {
	if len(code) > 160 {
		return false
	}
	if kind == "event" {
		return eventPattern.MatchString(code)
	}
	return (kind == "scope" || kind == "webhook") && permissionPattern.MatchString(code)
}

func validVisibleASCII(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range value {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func exactHTTPSOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || value == "" || value != strings.TrimSpace(value) || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" || parsed.String() != value {
		return nil, ErrInvalidConfiguration
	}
	return parsed, nil
}

func validateClientCertificate(certificate tls.Certificate, installationID uuid.UUID, now time.Time) (uuid.UUID, ed25519.PrivateKey, error) {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return uuid.Nil, nil, ErrInvalidConfiguration
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	privateKey, privateOK := certificate.PrivateKey.(ed25519.PrivateKey)
	publicKey, publicOK := leafPublicKey(leaf)
	if err != nil || !privateOK || len(privateKey) != ed25519.PrivateKeySize || !publicOK ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) || leaf.IsCA ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !allowsClientAuth(leaf) ||
		leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 || len(leaf.SerialNumber.Bytes()) != 16 ||
		len(leaf.URIs) != 1 || leaf.URIs[0] == nil || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 || leaf.URIs[0].String() != "spiffe://cdn-platform/installation/"+installationID.String() {
		return uuid.Nil, nil, ErrInvalidConfiguration
	}
	certificateID, err := uuid.FromBytes(leaf.SerialNumber.Bytes())
	if err != nil || certificateID.Version() != 7 || certificateID.Variant() != uuid.RFC4122 {
		return uuid.Nil, nil, ErrInvalidConfiguration
	}
	return certificateID, privateKey, nil
}

func newProjectionHTTPClient(tlsConfig *tls.Config, timeout time.Duration,
	dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	clone := tlsConfig.Clone()
	clone.MinVersion, clone.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	transport := &http.Transport{
		Proxy: nil, DialContext: dial, TLSClientConfig: clone, ForceAttemptHTTP2: true, DisableCompression: true,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: timeout,
		MaxResponseHeaderBytes: maximumResponseHeaderBytes,
	}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
}

func clearRuntimeCredential(credential *RuntimeCredential) {
	if credential == nil {
		return
	}
	clear(credential.PrivateKey)
	if key, ok := credential.TLSCertificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(key)
	}
	for i := range credential.TLSCertificate.Certificate {
		clear(credential.TLSCertificate.Certificate[i])
	}
	credential.PrivateKey = nil
	credential.TLSCertificate = tls.Certificate{}
	credential.RootCAs = nil
}

func leafPublicKey(leaf *x509.Certificate) (ed25519.PublicKey, bool) {
	if leaf == nil {
		return nil, false
	}
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	return key, ok && len(key) == ed25519.PublicKeySize
}

func allowsClientAuth(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func lengthPrefixed(fields ...any) []byte {
	result := make([]byte, 0, 256)
	for _, field := range fields {
		var value []byte
		switch typed := field.(type) {
		case string:
			value = []byte(typed)
		case []byte:
			value = typed
		default:
			panic("unsupported length-prefixed field")
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		result = append(result, size[:]...)
		result = append(result, value...)
	}
	return result
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
