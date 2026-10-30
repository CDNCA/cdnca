package acmeedge

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid ACME HTTP-01 overlay input")
	ErrIdempotencyConflict = errors.New("ACME HTTP-01 overlay idempotency conflict")
	ErrRevisionConflict    = errors.New("ACME HTTP-01 overlay revision conflict")
	ErrEntitlementDenied   = errors.New("ACME HTTP-01 overlay entitlement denied")
	ErrTargetIneligible    = errors.New("ACME HTTP-01 overlay target is ineligible")
	ErrChallengeIneligible = errors.New("ACME HTTP-01 challenge is ineligible")
	ErrEncryptionFailed    = errors.New("ACME HTTP-01 token encryption failed")
	ErrNotFound            = errors.New("ACME HTTP-01 overlay not found")
	ErrClaimLost           = errors.New("ACME HTTP-01 delivery claim lost")
	ErrReceiptConflict     = errors.New("ACME HTTP-01 receipt conflict")
	ErrInvalidTransition   = errors.New("invalid ACME HTTP-01 deployment transition")
	ErrStaleAttempt        = errors.New("stale ACME HTTP-01 deployment attempt")
	ErrAttemptsExhausted   = errors.New("ACME HTTP-01 deployment attempts exhausted")
	ErrPersistence         = errors.New("ACME HTTP-01 overlay persistence failed")
)

const (
	EntitlementStatusValid = "valid"
	EntitlementStatusGrace = "grace"
	ModeApply              = "apply"
	ModeCleanup            = "cleanup"
	DeploymentQueued       = "queued"
	DeploymentRetryQueued  = "retry_queued"
	DeploymentDispatched   = "dispatched"
	DeploymentApplied      = "applied"
	DeploymentHealthy      = "healthy"
	DeploymentFailed       = "failed"
	DeploymentTimedOut     = "timed_out"
)

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type EntitlementAuthorizer interface {
	AuthorizeOverlay(context.Context, pgx.Tx, EntitlementRequest) (EntitlementDecision, error)
}

type TargetResolver interface {
	ResolveOverlayTarget(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, TargetSnapshotReference) (TargetSnapshot, error)
}

type TokenCipher interface {
	Seal(context.Context, SealRequest) (SealResult, error)
}

type EntitlementRequest struct {
	TenantScopeID uuid.UUID
	SiteID        uuid.UUID
	TokenCount    int
	NodeCount     int
}

type EntitlementDecision struct {
	Allowed         bool
	LocallyVerified bool
	InGrace         bool
	Status          string
	LeaseSerial     uint64
	EvaluatedAt     time.Time
}

type TargetSnapshotReference struct {
	ID       uuid.UUID
	Revision int64
	SHA256   [32]byte
}

type TargetSnapshot struct {
	Reference TargetSnapshotReference
	NodeIDs   []uuid.UUID
}

type ChallengeReference struct {
	OperationID string
	AttemptID   uuid.UUID
}

type SealRequest struct {
	TenantScopeID      uuid.UUID
	SiteID             uuid.UUID
	OperationID        string
	ChallengeAttemptID uuid.UUID
	Domain             string
	Token              string
	ExactValue         string
	AAD                []byte
}

type SealResult struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

type SealedToken struct {
	Ordinal            int
	OperationID        string
	ChallengeAttemptID uuid.UUID
	Domain             string
	TokenSHA256        [32]byte
	ValueSHA256        [32]byte
	KeyID              string
	Nonce              []byte
	Ciphertext         []byte
	AADSHA256          [32]byte
}

type Config struct {
	Clock                 func() time.Time
	Cipher                TokenCipher
	EntitlementAuthorizer EntitlementAuthorizer
	TargetResolver        TargetResolver
	Auditor               AuditAppender
	SubjectPrefix         string
	RetryDelay            time.Duration
}

func DefaultConfig() Config {
	return Config{
		Clock: time.Now, SubjectPrefix: "edge.acme.http01", RetryDelay: 2 * time.Second,
	}
}

type PublishRequest struct {
	Mode             string
	TenantScopeID    uuid.UUID
	SiteID           uuid.UUID
	ExpectedRevision int64
	Challenges       []ChallengeReference
	NodeIDs          []uuid.UUID
	TargetSnapshot   *TargetSnapshotReference
	MaxAttempts      int
	Deadline         time.Time
	IdempotencyKey   string
	RequestID        string
}

type Publication struct {
	ID                   uuid.UUID
	VersionID            uuid.UUID
	Mode                 string
	TenantScopeID        uuid.UUID
	SiteID               uuid.UUID
	Revision             int64
	SealedSnapshotSHA256 [32]byte
	TokenCount           int
	NodeCount            int
	CreatedAt            time.Time
	Replayed             bool
}

type ClaimRequest struct {
	Limit         int
	LeaseDuration time.Duration
}

type SealedDelivery struct {
	OutboxID          uuid.UUID
	Mode              string
	LeaseToken        uuid.UUID
	LeaseExpiresAt    time.Time
	PublishAttempt    int
	DeploymentID      uuid.UUID
	DeploymentAttempt int
	TenantScopeID     uuid.UUID
	SiteID            uuid.UUID
	DomainRevision    int64
	VersionID         uuid.UUID
	NodeID            uuid.UUID
	Subject           string
	PayloadSHA256     [32]byte
	Tokens            []SealedToken
}

type CompleteDeliveryRequest struct {
	OutboxID    uuid.UUID
	LeaseToken  uuid.UUID
	Published   bool
	Retryable   bool
	FailureCode string
	RetryAfter  time.Duration
}

type Receipt struct {
	DeploymentID      uuid.UUID
	DeploymentAttempt int
	ReceiptID         uuid.UUID
	State             string
	FailureCode       string
	OccurredAt        time.Time
}

type DeploymentState struct {
	DeploymentID      uuid.UUID
	DeploymentAttempt int
	VersionID         uuid.UUID
	NodeID            uuid.UUID
	State             string
	Sequence          int64
	Deadline          time.Time
	OccurredAt        time.Time
	Replayed          bool
}

type RetryRequest struct {
	DeploymentID uuid.UUID
	Deadline     time.Time
	RequestID    string
}

type ReconcileRequest struct {
	Now            time.Time
	AttemptTimeout time.Duration
	Limit          int
}

type ReconcileResult struct {
	TimedOut int
	Retried  int
}

type Outbox struct {
	ID                uuid.UUID
	DeploymentID      uuid.UUID
	DeploymentAttempt int
	VersionID         uuid.UUID
	NodeID            uuid.UUID
	CreatedAt         time.Time
}

type Health struct {
	TenantScopeID uuid.UUID
	SiteID        uuid.UUID
	Revision      int64
	VersionID     uuid.UUID
	TargetCount   int
	HealthyCount  int
	FailedCount   int
	PendingCount  int
	Healthy       bool
}

type HealthyRevision struct {
	TenantScopeID  uuid.UUID
	SiteID         uuid.UUID
	Revision       int64
	VersionID      uuid.UUID
	SnapshotSHA256 [32]byte
	UpdatedAt      time.Time
}
