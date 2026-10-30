package notificationruntime

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

var (
	ErrInvalidConfig        = errors.New("notification_runtime_invalid_config")
	ErrDisabled             = errors.New("notification_runtime_disabled")
	ErrAlreadyRunning       = errors.New("notification_runtime_already_running")
	ErrWorkerNotRunning     = errors.New("notification_runtime_worker_not_running")
	ErrWorkerExited         = errors.New("notification_runtime_worker_exited")
	ErrChannelUnavailable   = errors.New("notification_runtime_channel_unavailable")
	ErrSenderUnavailable    = errors.New("notification_runtime_sender_unavailable")
	ErrSenderNotReady       = errors.New("notification_runtime_sender_not_ready")
	ErrProviderUnavailable  = errors.New("notification_runtime_provider_unavailable")
	ErrProviderNotReady     = errors.New("notification_runtime_provider_not_ready")
	ErrTemplateUnavailable  = errors.New("notification_runtime_template_unavailable")
	ErrDispatcherInvalid    = errors.New("notification_runtime_dispatcher_invalid")
	ErrDispatcherRegistered = errors.New("notification_runtime_dispatcher_registered")
	ErrEventTypeDenied      = errors.New("notification_runtime_event_type_denied")
	ErrRegistryClosed       = errors.New("notification_runtime_registry_closed")
	ErrCloseTimeout         = errors.New("notification_runtime_close_timeout")
	ErrProviderClose        = errors.New("notification_runtime_provider_close_failed")
)

type RuntimeState string

const (
	StateDisabled RuntimeState = "disabled"
	StateBuilt    RuntimeState = "built"
	StateRunning  RuntimeState = "running"
	StateReady    RuntimeState = "ready"
	StateBackoff  RuntimeState = "backoff"
	StateStopping RuntimeState = "stopping"
	StateStopped  RuntimeState = "stopped"
	StateFailed   RuntimeState = "failed"
)

type RuntimeConfig struct {
	Enabled                bool
	Worker                 notification.WorkerConfig
	RecoveryTemplates      map[notification.Channel]notification.TemplateRef
	IdleWait               time.Duration
	ErrorBackoffBase       time.Duration
	ErrorBackoffMax        time.Duration
	MaxConsecutiveFailures int
	SendTimeout            time.Duration
	ShutdownTimeout        time.Duration
	Logger                 *slog.Logger
	// TransientError reports a temporarily unavailable database. Such a batch
	// error ends Run with the original error without counting towards
	// MaxConsecutiveFailures, so the caller can back off and call Run again.
	TransientError func(error) bool
}

func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Worker: notification.DefaultWorkerConfig(), IdleWait: 500 * time.Millisecond,
		ErrorBackoffBase: 250 * time.Millisecond, ErrorBackoffMax: 30 * time.Second,
		MaxConsecutiveFailures: 8, SendTimeout: 10 * time.Second, ShutdownTimeout: 15 * time.Second,
	}
}

type Dependencies struct {
	Store          *notification.Store
	MemberContacts MemberContactResolver
	Providers      map[notification.Channel]ProviderTransport
}

type MemberContactResolver interface {
	Ready(context.Context, notification.Channel) error
	Resolve(context.Context, uuid.UUID, uuid.UUID, notification.Channel) ContactResolution
}

type ContactResolution struct {
	Contact string
	Failure *notification.Failure
}

type ProviderDisposition string

const (
	ProviderAccepted         ProviderDisposition = "accepted"
	ProviderUnknown          ProviderDisposition = "unknown"
	ProviderTemporaryFailure ProviderDisposition = "temporary_failure"
	ProviderPermanentFailure ProviderDisposition = "permanent_failure"
	ProviderRateLimited      ProviderDisposition = "rate_limited"
)

type ProviderMessage struct {
	OutboxID       uuid.UUID
	Channel        notification.Channel
	Contact        string
	Subject        string
	Body           string
	ActionURL      string
	IdempotencyKey string
	AttemptNumber  int
	// TemplateID and Params feed template-based SMS providers (aliyun,
	// submail): our template id is mapped to the provider template and each
	// param to a provider variable. Rendered Subject/Body stay authoritative
	// for every other transport.
	TemplateID string
	Params     map[string]string
	// ScopeID is the recipient's access scope (uuid.Nil when unknown, as for
	// account recovery): the email layout uses that tenant's theme (PA-26).
	ScopeID uuid.UUID
}

type ProviderResult struct {
	Disposition        ProviderDisposition
	Code               string
	RetryAfter         time.Duration
	ProviderDeliveryID string
}

// ProviderTransport adapters must honor context cancellation and must treat
// IdempotencyKey as the stable provider idempotency key when the provider supports one.
type ProviderTransport interface {
	Ready(context.Context) error
	Send(context.Context, ProviderMessage) (ProviderResult, error)
	Close(context.Context) error
}

type Registration interface {
	Close(context.Context) error
}

type HealthSnapshot struct {
	Enabled             bool
	State               RuntimeState
	Ready               bool
	WorkerRunning       bool
	EnabledChannels     int
	ConsecutiveFailures int
	LastErrorClass      string
}

var _ accountrecovery.RecoverySender = (*recoverySender)(nil)
var _ notification.Sender = (*memberSender)(nil)
