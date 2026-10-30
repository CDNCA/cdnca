package nodecertlifecycle

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid node certificate lifecycle input")
	ErrPermissionDenied    = errors.New("node certificate lifecycle permission denied")
	ErrNotFound            = errors.New("node certificate lifecycle resource not found")
	ErrIdempotencyConflict = errors.New("node certificate lifecycle idempotency conflict")
	ErrRevisionConflict    = errors.New("node certificate lifecycle revision conflict")
	ErrInstallationMissing = errors.New("control installation identity is unavailable")
	ErrCAEpochConflict     = errors.New("node CA key epoch conflict")
	ErrCAEpochRevoked      = errors.New("node CA key epoch is revoked")
	ErrCAEpochExpired      = errors.New("node CA key epoch is outside its validity period")
	ErrCertificateInvalid  = errors.New("node certificate is invalid")
	ErrCertificateRevoked  = errors.New("node certificate is revoked")
	ErrCertificateExpired  = errors.New("node certificate is expired")
	ErrRenewalTooEarly     = errors.New("node certificate renewal is too early")
	ErrRenewalNotProven    = errors.New("node certificate renewal has no accepted proof-of-possession fact")
	ErrOverlapActive       = errors.New("previous node certificate overlap is still active")
	ErrPersistence         = errors.New("node certificate lifecycle persistence failed")
)

const (
	EpochActive  = "active"
	EpochRetired = "retired"
	EpochRevoked = "revoked"

	RotationLegacyUnbound = "legacy_unbound"
	RotationCurrent       = "current"
	RotationOverlap       = "overlap"
	RotationRetired       = "retired"

	ProofLegacyUnbound = "legacy_unbound"
	ProofGatewayMTLS   = "gateway_mtls_proven"
	ProofCryptographic = "cryptographic_proven"
)

type Clock func() time.Time

type Config struct {
	Clock                    Clock
	OverlapWindow            time.Duration
	AuthorizationSnapshotTTL time.Duration
	MaxScheduledRevocation   time.Duration
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type RotateCAEpochRequest struct {
	RequestID            uuid.UUID
	ExpectedCurrentEpoch int64
	KeyID                string
	CACertificatePEM     []byte
	RequestTraceID       string
}

type CAEpoch struct {
	ID             uuid.UUID
	InstallationID string
	Epoch          int64
	KeyID          string
	Status         string
	NotBefore      time.Time
	NotAfter       time.Time
	CreatedAt      time.Time
	Replayed       bool
}

type RevokeCAEpochRequest struct {
	RequestID      uuid.UUID
	EpochID        uuid.UUID
	Reason         string
	RequestTraceID string
}

type AdoptCertificateRequest struct {
	RequestID      uuid.UUID
	NodeID         uuid.UUID
	SerialNumber   string
	LeafDERSHA256  [32]byte
	CAEpochID      uuid.UUID
	RequestTraceID string
}

type CertificateState struct {
	CertificateID  uuid.UUID
	NodeID         uuid.UUID
	OwnerScopeID   uuid.UUID
	InstallationID string
	SerialNumber   string
	LeafDERSHA256  [32]byte
	CAEpochID      uuid.UUID
	RotationStatus string
	Status         string
	Revision       int64
	NotBefore      time.Time
	NotAfter       time.Time
	RenewalAt      time.Time
	OverlapUntil   *time.Time
	Replayed       bool
}

type RecordGatewayMTLSProofRequest struct {
	RenewalRequestID     uuid.UUID
	NodeID               uuid.UUID
	CurrentSerialNumber  string
	CurrentLeafDERSHA256 [32]byte
	TargetCAEpochID      uuid.UUID
	Principal            GatewayMTLSPrincipal
	RequestTraceID       string
}

// GatewayMTLSPrincipal is minted only after the control-internal mTLS adapter
// authenticates the Gateway workload. Callers must not copy an unauthenticated
// client header into this value.
type GatewayMTLSPrincipal struct {
	workloadIdentity string
	instanceID       string
}

func NewGatewayMTLSPrincipal(workloadIdentity, instanceID string) (GatewayMTLSPrincipal, error) {
	principal := GatewayMTLSPrincipal{workloadIdentity: workloadIdentity, instanceID: instanceID}
	if !validGatewayMTLSPrincipal(principal) {
		return GatewayMTLSPrincipal{}, ErrInvalidInput
	}
	return principal, nil
}

type RenewalProofFact struct {
	RenewalRequestID     uuid.UUID
	NodeID               uuid.UUID
	OwnerScopeID         uuid.UUID
	InstallationID       string
	CurrentSerialNumber  string
	CurrentLeafDERSHA256 [32]byte
	TargetCAEpochID      uuid.UUID
	CSRSHA256            [32]byte
	MessageSHA256        [32]byte
	Status               string
	Revision             int64
	ObservedAt           time.Time
	RotationBoundAt      *time.Time
	OverlapUntil         *time.Time
	Replayed             bool
	newSerialNumber      string
}

type BindIssuedRenewalRequest struct {
	RenewalRequestID uuid.UUID
	NodeID           uuid.UUID
	NewSerialNumber  string
	NewLeafDERSHA256 [32]byte
	RequestTraceID   string
}

type RotationResult struct {
	Proof                 RenewalProofFact
	CurrentCertificate    CertificateState
	PreviousCertificate   CertificateState
	AuthorizationRevision uint64
	Replayed              bool
}

type RevokeCertificateRequest struct {
	RequestID      uuid.UUID
	NodeID         uuid.UUID
	SerialNumber   string
	LeafDERSHA256  [32]byte
	Reason         string
	EffectiveAt    time.Time
	RequestTraceID string
}

type Revocation struct {
	RequestID             uuid.UUID
	CertificateID         uuid.UUID
	NodeID                uuid.UUID
	OwnerScopeID          uuid.UUID
	InstallationID        string
	SerialNumber          string
	Reason                string
	EffectiveAt           time.Time
	RequestedAt           time.Time
	AuthorizationRevision uint64
	Replayed              bool
}

type LookupRequest struct {
	NodeID        uuid.UUID
	SerialNumber  string
	LeafDERSHA256 [32]byte
}

type AuthorizationSnapshot struct {
	NodeID                uuid.UUID
	OwnerScopeID          uuid.UUID
	InstallationID        string
	CertificateID         uuid.UUID
	SerialNumber          string
	LeafDERSHA256         [32]byte
	CAEpochID             uuid.UUID
	CAEpoch               int64
	AuthorizationRevision uint64
	AdministrativeState   string
	CertificateStatus     string
	RotationStatus        string
	ConnectionAllowed     bool
	DeploymentsAllowed    bool
	DenialReason          string
	CertificateNotBefore  time.Time
	CertificateNotAfter   time.Time
	OverlapUntil          *time.Time
	SnapshotExpiresAt     time.Time
}
