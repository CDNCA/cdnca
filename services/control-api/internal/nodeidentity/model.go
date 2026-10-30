package nodeidentity

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput          = errors.New("invalid node identity input")
	ErrInvalidToken          = errors.New("invalid enrollment token")
	ErrTokenExpired          = errors.New("enrollment token expired")
	ErrTokenConsumed         = errors.New("enrollment token consumed")
	ErrIdempotencyConflict   = errors.New("node identity request conflict")
	ErrEnrollmentDenied      = errors.New("node enrollment denied")
	ErrAuthorizationNotFound = errors.New("node identity authorization not found")
	ErrAuthorizationExpired  = errors.New("node identity authorization expired")
	ErrGatewayBinding        = errors.New("gateway identity does not match authorization")
	ErrIssuanceInProgress    = errors.New("certificate issuance is already in progress")
	ErrSigningFailed         = errors.New("node certificate signing failed")
	ErrCertificateInvalid    = errors.New("signed node certificate is invalid")
	ErrCertificateNotFound   = errors.New("node certificate not found")
	ErrCertificateRevoked    = errors.New("node certificate is revoked")
	ErrRenewalConflict       = errors.New("node certificate already has a renewal")
	ErrRenewalTooEarly       = errors.New("node certificate renewal is too early")
	ErrNodeStateDenied       = errors.New("node administrative state denies this operation")
	ErrPersistence           = errors.New("node identity persistence failed")
)

const NodeSPIFFEPrefix = "spiffe://cdn-platform/node/"

const (
	RenewalReasonTooEarly       = "renewal_too_early"
	RenewalReasonRequestExpired = "renewal_request_expired"
)

type RenewalRetryError struct {
	Cause      error
	Reason     string
	RetryAt    time.Time
	RetryAfter time.Duration
}

func (e *RenewalRetryError) Error() string {
	if e == nil || e.Cause == nil {
		return "node certificate renewal retry"
	}
	return e.Cause.Error()
}

func (e *RenewalRetryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func renewalRetryError(cause error, reason string, retryAt, now time.Time) error {
	retryAt = retryAt.UTC().Truncate(time.Second)
	now = now.UTC().Truncate(time.Second)
	retryAfter := retryAt.Sub(now)
	if retryAfter < 0 {
		retryAfter = 0
	}
	return &RenewalRetryError{Cause: cause, Reason: reason, RetryAt: retryAt, RetryAfter: retryAfter}
}

type Clock func() time.Time

type IDGenerator func() (uuid.UUID, error)

type Config struct {
	AcceptedProtocols   *commonv1.ProtocolVersionRange
	AuthorizationTTL    time.Duration
	RenewalRequestTTL   time.Duration
	CertificateTTL      time.Duration
	CertificateBackdate time.Duration
	RenewBefore         time.Duration
	SigningLeaseTTL     time.Duration
	SnapshotTTL         time.Duration
	// RecoveryWindow bounds how long after NotAfter an expired certificate may still be
	// recovered with the same key (ADR 0013 §6.1 b).
	RecoveryWindow time.Duration
	Clock          Clock
	NewID          IDGenerator
}

// Node certificate lifetime parameters (ADR 0013 §6.1, §8 items 2/3; user-adjustable defaults).
const (
	DefaultCertificateTTL     = 30 * 24 * time.Hour
	DefaultRenewBefore        = DefaultCertificateTTL / 2
	MaxCertificateTTL         = 31 * 24 * time.Hour
	DefaultRecoveryWindow     = 180 * 24 * time.Hour
	MaxRecoveryWindow         = 3650 * 24 * time.Hour
	RecoveryRequestMaxSkew    = 5 * time.Minute
	RecoveryProofSignatureTag = "cdnca/node-certificate-recovery/v1"
)

type AuthorizeRequest struct {
	RequestID                    string
	EnrollmentToken              string
	CertificateSigningRequestDER []byte
	MachineFingerprintSHA256     []byte
	SupportedProtocolVersions    *commonv1.ProtocolVersionRange
	Capabilities                 *agentv1.AgentCapabilities
	GatewayWorkloadIdentity      string
	GatewayInstanceID            string
	PeerIP                       string
	ArtifactEncryptionPublicKey  []byte
}

type Authorization struct {
	ID                              uuid.UUID
	NodeID                          uuid.UUID
	CertificateSigningRequestSHA256 [32]byte
	SelectedProtocolVersion         *commonv1.ProtocolVersion
	ExpiresAt                       time.Time
	ArtifactEncryptionKeyID         string
	Replayed                        bool
}

type CompleteRequest struct {
	RequestID               string
	AuthorizationID         uuid.UUID
	GatewayWorkloadIdentity string
	GatewayInstanceID       string
}

type RenewRequest struct {
	RequestID                    string
	NodeID                       uuid.UUID
	CurrentSerialNumber          string
	CurrentCertificateSHA256     [32]byte
	CertificateSigningRequestDER []byte
	GatewayWorkloadIdentity      string
	GatewayInstanceID            string
}

type RevokeRequest struct {
	RequestID    string
	NodeID       uuid.UUID
	SerialNumber string
	Reason       string
}

type GetAuthorizationRequest struct {
	NodeID                  uuid.UUID
	CertificateSerialNumber string
	CertificateSHA256       [32]byte
	GatewayWorkloadIdentity string
	GatewayInstanceID       string
	SessionFacts            *controlv1.GatewaySessionFactsV1
}

type Certificate struct {
	ID                 uuid.UUID
	NodeID             uuid.UUID
	LeafCertificatePEM []byte
	IssuingChainPEM    [][]byte
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	RenewalAt          time.Time
}

type EnrollmentCompletion struct {
	Certificate             Certificate
	ArtifactEncryptionKeyID string
}

type AuthorizationSnapshot struct {
	NodeID         uuid.UUID
	InstallationID string
	TenantID       uuid.UUID
	// NodeScopeID owns the node (nodes.scope_id): the platform scope for a
	// shared node. Host firewall rules of a tenant apply only on its own (A08).
	NodeScopeID               uuid.UUID
	TelemetrySites            []TelemetrySiteScope
	AuthorizationRevision     uint64
	AdministrativeState       string
	ConnectionAllowed         bool
	DeploymentsAllowed        bool
	CertificateRevoked        bool
	CertificateExpirationTime time.Time
	AcceptedProtocolVersions  *commonv1.ProtocolVersionRange
	SnapshotExpirationTime    time.Time
	ArtifactEncryptionKeyID   string
	SessionFactsSHA256        []byte
	// TelemetryExcludedScopes names, with a TelemetryExclusion* reason, the
	// scopes of a node serving several whose telemetry was left out.
	TelemetryExcludedScopes map[uuid.UUID]string
}

type TelemetrySiteScope struct {
	SiteID   uuid.UUID
	TenantID uuid.UUID
	// ConfigurationScopeID is the scope that published ConfigVersionID; a
	// scoped gateway session attributes the site's telemetry through it.
	ConfigurationScopeID  uuid.UUID
	ConfigVersionID       uuid.UUID
	PackageSubscriptionID uuid.UUID
}

type SignRequest struct {
	NodeID                       uuid.UUID
	CertificateSigningRequestDER []byte
	URISAN                       string
	NotBefore                    time.Time
	NotAfter                     time.Time
	IssuanceKind                 string
}

type SignedCertificate struct {
	LeafCertificatePEM []byte
	IssuingChainPEM    [][]byte
}

// CertificateSigner owns CA credentials. Implementations must not persist or
// return the Agent private key; the request contains only a public PKCS#10 CSR.
type CertificateSigner interface {
	SignNodeCertificate(context.Context, SignRequest) (SignedCertificate, error)
}
