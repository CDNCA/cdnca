package accountregistrationchallenge

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidConfig        = errors.New("invalid account registration challenge config")
	ErrInvalidInput         = errors.New("invalid account registration challenge input")
	ErrHumanInvalid         = errors.New("account registration human challenge invalid")
	ErrHumanUnavailable     = errors.New("account registration human verifier unavailable")
	ErrContactUnavailable   = errors.New("account registration contact delivery unavailable")
	ErrOTPInvalid           = errors.New("account registration verification code invalid")
	ErrRateLimited          = errors.New("account registration challenge rate limited")
	ErrIdempotencyConflict  = errors.New("account registration challenge idempotency conflict")
	ErrChallengeUnavailable = errors.New("account registration challenge unavailable")
	ErrRegistrationDisabled = errors.New("account registration disabled")
	ErrPolicyUnavailable    = errors.New("account registration policy unavailable")
)

type CreateInput struct {
	ScopeID        uuid.UUID
	Username       string
	Email          string
	Phone          string
	Channel        string
	Source         string
	HumanToken     string
	IdempotencyKey string
	RequestID      string
}

type CreateResult struct {
	ChallengeID uuid.UUID
	ExpiresAt   time.Time
	Replayed    bool
}

type VerifyInput struct {
	ScopeID        uuid.UUID
	ChallengeID    uuid.UUID
	Username       string
	Email          string
	Phone          string
	Channel        string
	Source         string
	OTP            string
	IdempotencyKey string
	RequestID      string
}

type VerifyResult struct {
	Reference string
	ExpiresAt time.Time
	Replayed  bool
}

type HumanVerification struct {
	Token          string
	Source         string
	IdempotencyKey string
}

type HumanVerifier interface {
	Verify(context.Context, HumanVerification) error
}

type ProofIssuer interface {
	Issue(context.Context, accountregistrationproof.IssueRequest) (accountregistrationproof.IssueResult, error)
}

type ContactRequest struct {
	ScopeID           uuid.UUID
	ChallengeID       uuid.UUID
	Channel           notification.Channel
	Template          notification.TemplateRef
	Destination       string
	DestinationDigest [32]byte
	OTP               string
	ExpiresAt         time.Time
	RequestID         string
}

type ContactReceipt struct {
	AnonymousDispatchReference uuid.UUID
	OutboxID                   uuid.UUID
}

type ContactSender interface {
	Enqueue(context.Context, pgx.Tx, ContactRequest) (ContactReceipt, error)
}

type RegistrationDispatchEnqueuer interface {
	EnqueueDispatchTx(context.Context, pgx.Tx, notification.DispatchEnqueueRequest) (notification.EnqueueResult, error)
}

type ContactDelivery struct {
	OutboxID       uuid.UUID
	Channel        notification.Channel
	Template       notification.TemplateRef
	Destination    string
	OTP            string
	Subject        string
	Body           string
	IdempotencyKey string
	AttemptNumber  int
}

type ContactProvider interface {
	SendRegistrationVerification(context.Context, ContactDelivery) notification.SendResult
}

type Config struct {
	DigestKey        []byte
	PublicSettings   systemusersettingsReader
	TemplateSettings registrationVerificationTemplateReader
	Clock            func() time.Time
	Entropy          io.Reader
	ChallengeTTL     time.Duration
	MaxAttempts      int
	RateWindow       time.Duration
	SourceLimit      int
	SubjectLimit     int
}

type systemusersettingsReader interface {
	GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error)
}

type registrationVerificationTemplateReader interface {
	GetRegistrationVerificationTemplate(
		context.Context,
		uuid.UUID,
		notification.Channel,
	) (notification.TemplateRef, bool, error)
}
