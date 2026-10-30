package accountloginchallenge

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidConfig       = errors.New("invalid account login challenge config")
	ErrInvalidInput        = errors.New("invalid account login challenge input")
	ErrMethodDisabled      = errors.New("account login method disabled")
	ErrHumanRequired       = errors.New("account login human verification required")
	ErrHumanInvalid        = errors.New("account login human verification invalid")
	ErrRateLimited         = errors.New("account login challenge rate limited")
	ErrIdempotencyConflict = errors.New("account login challenge idempotency conflict")
	ErrOTPInvalid          = errors.New("account login verification code invalid")
	ErrChallengeUsed       = errors.New("account login challenge already used")
	ErrUnavailable         = errors.New("account login challenge unavailable")
)

type Methods struct {
	// RegistrationEnabled: the registration switch is on and the registration
	// endpoints are mounted, so the sign-in page may offer a sign-up link.
	RegistrationEnabled bool
	EmailEnabled        bool
	SMSEnabled          bool
	EmailAntiAbuseMode  string
	SMSAntiAbuseMode    string
	// Set only when a channel uses tencent or geetest_v4, for the browser widget.
	CaptchaProvider string
	CaptchaAppID    string
}

type CreateInput struct {
	ScopeID         uuid.UUID
	Identifier      string
	Channel         notification.Channel
	Source          string
	HumanToken      string
	IdempotencyKey  string
	RequestID       string
	passwordSubject *identity.PasswordLoginChallengeSubject
}

type CreateResult struct {
	ChallengeID uuid.UUID
	ExpiresAt   time.Time
	Replayed    bool
}

type VerifyInput struct {
	ScopeID        uuid.UUID
	ChallengeID    uuid.UUID
	Identifier     string
	Channel        notification.Channel
	Source         string
	OTP            string
	IdempotencyKey string
	RequestID      string
	UserAgent      string
}

type VerifyResult struct {
	Auth identity.AuthResult
}

type HumanVerifier interface {
	Verify(context.Context, string, string, string) error
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

type ContactSender interface {
	Enqueue(context.Context, pgx.Tx, ContactRequest) error
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
	SendLoginVerification(context.Context, ContactDelivery) notification.SendResult
}

type SessionIssuer interface {
	LoginVerified(context.Context, identity.VerifiedLoginInput, identity.RequestInfo) (identity.AuthResult, error)
}

type PolicyReader interface {
	GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error)
}

type TemplateReader interface {
	GetRegistrationVerificationTemplate(context.Context, uuid.UUID, notification.Channel) (notification.TemplateRef, bool, error)
}

type DispatchEnqueuer interface {
	EnqueueDispatchTx(context.Context, pgx.Tx, notification.DispatchEnqueueRequest) (notification.EnqueueResult, error)
}

type Config struct {
	DigestKey         []byte
	Policy            PolicyReader
	Templates         TemplateReader
	Human             HumanVerifier
	Issuer            SessionIssuer
	Contacts          ContactSender
	Clock             func() time.Time
	Entropy           io.Reader
	ChallengeTTL      time.Duration
	RateWindow        time.Duration
	SourceLimit       int
	SubjectLimit      int
	MaxAttempts       int
	AvailableChannels []notification.Channel
	// RegistrationMounted is false when the registration runtime is off; the
	// public methods then never advertise registration.
	RegistrationMounted bool
}
