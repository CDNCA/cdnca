package accountrecovery

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid account recovery input")
	ErrScopeMismatch       = errors.New("account recovery scope mismatch")
	ErrRateLimited         = errors.New("account recovery rate limited")
	ErrInvalidToken        = errors.New("invalid account recovery token")
	ErrPasswordPolicy      = errors.New("password does not satisfy policy")
	ErrPasswordReused      = errors.New("new password reuses current password")
	ErrPrincipalChanged    = errors.New("account recovery principal changed")
	ErrIdempotencyConflict = errors.New("account recovery idempotency conflict")
	ErrDispatchUnavailable = errors.New("account recovery dispatch unavailable")
	ErrUnavailable         = errors.New("account recovery unavailable")
)

type RequestContext struct {
	RequestID string
	TraceID   string
	SourceIP  string
}

type RequestInput struct {
	TenantID       uuid.UUID
	ScopeID        uuid.UUID
	Username       string
	IdempotencyKey string
	Context        RequestContext
}

type RequestResult struct {
	AcceptedAt time.Time
}

type ResetInput struct {
	TenantID        uuid.UUID
	ScopeID         uuid.UUID
	Token           string
	NewPassword     string
	ConfirmPassword string
	IdempotencyKey  string
	Context         RequestContext
}

type ResetResult struct {
	CompletedAt time.Time
	Replayed    bool
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type DispatchEnqueuer interface {
	EnqueueDispatchTx(context.Context, pgx.Tx, notification.DispatchEnqueueRequest) (notification.EnqueueResult, error)
}

type DispatchTemplateResolver interface {
	GetAccountRecoveryTemplate(
		context.Context,
		uuid.UUID,
		notification.Channel,
	) (notification.TemplateRef, bool, error)
}

type Config struct {
	Clock             func() time.Time
	Entropy           io.Reader
	DigestKey         []byte
	TokenTTL          time.Duration
	RateWindow        time.Duration
	SubjectLimit      int
	SourceLimit       int
	DispatchKeyring   *DispatchKeyring
	DispatchEnqueuer  DispatchEnqueuer
	DispatchTemplates map[notification.Channel]notification.TemplateRef
	TemplateResolver  DispatchTemplateResolver
}

type RecoveryDelivery struct {
	OutboxID       uuid.UUID
	Channel        notification.Channel
	Contact        string
	Subject        string
	Body           string
	RecoveryURL    string
	IdempotencyKey string
	AttemptNumber  int
	// TemplateID/Params feed template-based SMS providers.
	TemplateID string
	Params     map[string]string
}

type RecoverySender interface {
	SendRecovery(context.Context, RecoveryDelivery) notification.SendResult
}

type DispatcherConfig struct {
	Clock       func() time.Time
	DigestKey   []byte
	Keyring     *DispatchKeyring
	RecoveryURL string
	Sender      RecoverySender
}
