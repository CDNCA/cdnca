package accountregistration

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	VerificationEmail = "email"
	VerificationSMS   = "sms"
)

var (
	ErrInvalidInput                  = errors.New("invalid account registration input")
	ErrInvalidService                = errors.New("invalid account registration service")
	ErrInvalidStore                  = errors.New("invalid account registration store")
	ErrRegistrationDisabled          = errors.New("account registration disabled")
	ErrRegistrationPolicyUnavailable = errors.New("account registration policy unavailable")
	ErrIdempotencyConflict           = errors.New("account registration idempotency conflict")
	ErrRateLimited                   = errors.New("account registration rate limited")
	ErrRateLimitUnavailable          = errors.New("account registration rate limit unavailable")
	ErrProofInvalid                  = errors.New("account registration proof invalid")
	ErrProofUnavailable              = errors.New("account registration proof unavailable")
	ErrIncompleteReceipt             = errors.New("account registration receipt is incomplete")
)

type RegisterInput struct {
	ScopeID             uuid.UUID
	Username            string
	Password            string
	DisplayName         string
	Email               string
	Phone               string
	TermsAccepted       bool
	TermsVersion        string
	VerificationChannel string
	IdempotencyKey      string
	RequestID           string
	Source              string
	ProofReference      string `json:"-"`
}

type RegisterResult struct {
	Accepted bool `json:"accepted"`
	Replayed bool `json:"replayed"`
}

type RateLimitRequest struct {
	Source         string
	SubjectDigest  [32]byte
	IdempotencyKey string
}

type RateLimiter interface {
	Allow(context.Context, RateLimitRequest) (bool, error)
}

type RegistrationProofRequest struct {
	Reference      string
	Channel        string
	Destination    string
	Source         string
	IdempotencyKey string
	SubjectDigest  [32]byte
}

type RegistrationProof struct {
	EvidenceID        uuid.UUID
	Channel           string
	Destination       string
	HumanVerifiedAt   time.Time
	ContactVerifiedAt time.Time
	ExpiresAt         time.Time
}

type ProofAuthority interface {
	// VerifyAndConsume must replay the same evidence for the same idempotency key.
	VerifyAndConsume(context.Context, RegistrationProofRequest) (RegistrationProof, error)
}

type ServiceConfig struct {
	DigestKey      []byte
	ProofAuthority ProofAuthority
	PublicSettings PublicSettingsReader
	Clock          func() time.Time
}

// RegistrationSuccessTemplateReader resolves the immutable email template
// published by the platform user-settings revision. Variables are returned so
// the registration transaction can build an exact, non-sensitive context.
type RegistrationSuccessTemplateReader interface {
	GetRegistrationSuccessTemplateTx(
		context.Context,
		pgx.Tx,
		uuid.UUID,
	) (notification.TemplateRef, []string, bool, error)
}

type PublicSettingsReader interface {
	GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error)
}

type Registrar interface {
	Register(context.Context, RegistrationRecord) (StoreResult, error)
}

type RegistrationRecord struct {
	RegistrationID      uuid.UUID
	TenantID            uuid.UUID
	ScopeID             uuid.UUID
	UserID              uuid.UUID
	OwnerRoleID         uuid.UUID
	ViewerRoleID        uuid.UUID
	VerificationID      uuid.UUID
	Username            string
	PasswordHash        string
	DisplayName         string
	Email               string
	Phone               string
	TermsVersion        string
	VerificationChannel string
	IdempotencyKey      string
	RequestID           string
	RequestDigest       [32]byte
	SubjectDigest       [32]byte
	CreatedAt           time.Time
}

type StoreResult struct {
	Replayed bool
}
