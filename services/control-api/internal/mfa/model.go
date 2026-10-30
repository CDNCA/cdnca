package mfa

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	MethodTOTP         = "totp"
	MethodRecoveryCode = "recovery_code"
	StatusInactive     = "inactive"
	StatusPending      = "enrollment_pending"
	StatusActive       = "active"

	TOTPPeriod        = 30 * time.Second
	TOTPDigits        = 6
	TOTPWindow        = 1
	RecoveryCodeCount = 10
	MaxStepUpTTL      = 5 * time.Minute
	MaxProofUses      = 5

	defaultEnrollmentTTL = 10 * time.Minute
)

var (
	ErrInvalidInput          = errors.New("invalid MFA input")
	ErrInvalidSession        = errors.New("invalid authentication session")
	ErrPrincipalChanged      = errors.New("MFA principal changed")
	ErrTenantUnavailable     = errors.New("MFA tenant unavailable")
	ErrEncryptionUnavailable = errors.New("MFA encryption unavailable")
	ErrAlreadyEnabled        = errors.New("MFA is already enabled")
	ErrEnrollmentPending     = errors.New("MFA enrollment is pending")
	ErrEnrollmentExpired     = errors.New("MFA enrollment expired")
	ErrNotActive             = errors.New("MFA is not active")
	ErrAlreadyActive         = errors.New("MFA is already active")
	ErrInvalidCode           = errors.New("invalid MFA code")
	ErrCodeReplayed          = errors.New("MFA code counter replayed")
	ErrRecoveryCodeUsed      = errors.New("MFA recovery code already used")
	ErrIdempotencyConflict   = errors.New("MFA idempotency conflict")
	ErrInvalidProof          = errors.New("invalid step-up proof")
	ErrProofBinding          = errors.New("step-up proof binding mismatch")
	ErrProofExpired          = errors.New("step-up proof expired")
	ErrProofConsumed         = errors.New("step-up proof use limit reached")
	ErrUnavailable           = errors.New("MFA unavailable")
)

type EnvelopeCipher interface {
	Encrypt([]byte) (keyID string, ciphertext []byte, err error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Config struct {
	Clock         func() time.Time
	Random        io.Reader
	Issuer        string
	EnrollmentTTL time.Duration
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
}

type RequestContext struct {
	RequestID string
	TraceID   string
}

type StatusResult struct {
	Status              string
	CredentialID        uuid.UUID
	Method              string
	EnrollmentExpiresAt *time.Time
}

type EnrollmentRequest struct {
	AccountLabel   string
	IdempotencyKey string
	Context        RequestContext
}

type EnrollmentResult struct {
	CredentialID    uuid.UUID
	Secret          string
	ProvisioningURI string
	ExpiresAt       time.Time
	Replayed        bool
}

type ActivationRequest struct {
	CredentialID   uuid.UUID
	Code           string
	IdempotencyKey string
	Context        RequestContext
}

type ActivationResult struct {
	CredentialID  uuid.UUID
	RecoveryCodes []string
	ActivatedAt   time.Time
	Replayed      bool
}

type Authentication struct {
	Method string
	Code   string
}

type StepUpRequest struct {
	// TenantID binds the proof to one tenant. PlatformScope instead issues a
	// platform-scoped proof (TenantID must be uuid.Nil and the session must be
	// a platform session) for platform-level sensitive operations.
	TenantID       uuid.UUID
	PlatformScope  bool
	Audience       string
	Action         string
	Authentication Authentication
	TTL            time.Duration
	MaxUses        int
	IdempotencyKey string
	Context        RequestContext
}

type StepUpResult struct {
	ProofID   uuid.UUID
	Token     string
	Method    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	MaxUses   int
	Replayed  bool
}

type ConsumeStepUpRequest struct {
	Token    string
	TenantID uuid.UUID
	// PlatformScope consumes a platform-scoped proof (TenantID uuid.Nil);
	// tenant-bound proofs never satisfy it and vice versa.
	PlatformScope         bool
	Audience              string
	Action                string
	ResourceBindingDigest []byte
	Context               RequestContext
}

type Evidence struct {
	ProofID               uuid.UUID
	ActorUserID           uuid.UUID
	ActorScopeID          uuid.UUID
	SessionID             uuid.UUID
	TenantID              uuid.UUID
	PlatformScope         bool
	Method                string
	Audience              string
	Action                string
	VerifiedAt            time.Time
	ExpiresAt             time.Time
	UseOrdinal            int
	ResourceBindingDigest []byte
}

type DeactivateRequest struct {
	Authentication Authentication
	Reason         string
	IdempotencyKey string
	Context        RequestContext
}
