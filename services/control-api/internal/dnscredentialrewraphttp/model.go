package dnscredentialrewraphttp

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

const (
	CollectionRoute  = "/v1/admin/dns-credential-rewrap/jobs"
	PermissionManage = "platform.admin"
	MaxBatchItems    = 100

	CodeInvalidRequest         = "dns_credential_rewrap_invalid_request"
	CodeAuthenticationRequired = "dns_credential_rewrap_authentication_required"
	CodePermissionDenied       = "dns_credential_rewrap_permission_denied"
	CodeJobNotFound            = "dns_credential_rewrap_job_not_found"
	CodeIdempotencyConflict    = "dns_credential_rewrap_idempotency_conflict"
	CodeUnavailable            = "dns_credential_rewrap_unavailable"
	CodeMethodNotAllowed       = "dns_credential_rewrap_method_not_allowed"

	ItemCodeRevisionConflict      = "revision_conflict"
	ItemCodeProviderNotFound      = "provider_not_found"
	ItemCodeCredentialUnavailable = "credential_unavailable"
	ItemCodeIdempotencyConflict   = "idempotency_conflict"
	ItemCodeOperationFailed       = "operation_failed"
)

var (
	ErrInvalidConfig       = errors.New("DNS credential rewrap HTTP configuration invalid")
	ErrInvalidRequest      = errors.New("DNS credential rewrap request invalid")
	ErrUnauthenticated     = errors.New("DNS credential rewrap authentication required")
	ErrPermissionDenied    = errors.New("DNS credential rewrap permission denied")
	ErrJobNotFound         = errors.New("DNS credential rewrap job not found")
	ErrIdempotencyConflict = errors.New("DNS credential rewrap idempotency conflict")
	ErrUnavailable         = errors.New("DNS credential rewrap unavailable")
)

type JobState string

const (
	JobProcessing          JobState = "processing"
	JobCompleted           JobState = "completed"
	JobCompletedWithErrors JobState = "completed_with_errors"
)

type ItemStatus string

const (
	ItemPending   ItemStatus = "pending"
	ItemCompleted ItemStatus = "completed"
	ItemReplayed  ItemStatus = "replayed"
	ItemConflict  ItemStatus = "conflict"
	ItemFailed    ItemStatus = "failed"
)

type Owner struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
}

func (owner Owner) valid() bool {
	return owner.UserID != uuid.Nil && owner.ScopeID != uuid.Nil && owner.SessionID != uuid.Nil
}

type BatchItem struct {
	ProviderID       uuid.UUID `json:"provider_id"`
	ExpectedRevision int64     `json:"expected_revision"`
}

type ItemProgress struct {
	ProviderID        uuid.UUID  `json:"provider_id"`
	ExpectedRevision  int64      `json:"expected_revision"`
	Status            ItemStatus `json:"status"`
	Revision          int64      `json:"revision,omitempty"`
	CredentialVersion int64      `json:"credential_version,omitempty"`
	ErrorCode         string     `json:"error_code,omitempty"`
}

type Job struct {
	ID          uuid.UUID      `json:"job_id"`
	State       JobState       `json:"status"`
	Requested   int            `json:"requested"`
	Completed   int            `json:"completed"`
	Succeeded   int            `json:"succeeded"`
	Replayed    int            `json:"replayed"`
	Conflicted  int            `json:"conflicted"`
	Failed      int            `json:"failed"`
	Items       []ItemProgress `json:"items"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	CompletedAt time.Time      `json:"completed_at,omitempty"`
}

type SubmitRequest struct {
	Owner          Owner
	IdempotencyKey string
	RequestID      string
	Items          []BatchItem
}

type GetRequest struct {
	Owner Owner
	JobID uuid.UUID
}

type Authorizer interface {
	Authorize(context.Context, string) (Owner, error)
}

type Domain interface {
	Submit(context.Context, SubmitRequest) (Job, bool, error)
	Get(context.Context, GetRequest) (Job, error)
}

type Rewrapper interface {
	RewrapProviderCredentials(context.Context, dnsacme.Actor, dnsacme.CredentialRewrapRequest) (dnsacme.CredentialRewrapProgress, error)
}

type ClaimRequest struct {
	Owner          Owner
	IdempotencyKey string
	Digest         [32]byte
	Items          []BatchItem
}

type Claim struct {
	ID        uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	Items     []BatchItem
	Complete  bool
	Job       Job
}

type CompleteItemRequest struct {
	Owner   Owner
	JobID   uuid.UUID
	Ordinal int
	Item    ItemProgress
}

type CompleteRequest struct {
	Owner Owner
	Job   Job
}

type Repository interface {
	Claim(context.Context, ClaimRequest) (Claim, error)
	ItemCompleted(context.Context, Owner, string) (bool, error)
	Item(context.Context, Owner, uuid.UUID, int) (ItemProgress, bool, error)
	CompleteItem(context.Context, CompleteItemRequest) (ItemProgress, error)
	Complete(context.Context, CompleteRequest) (Job, error)
	Get(context.Context, GetRequest) (Job, error)
	WithJobLock(context.Context, uuid.UUID, func(context.Context) error) (bool, error)
}

type Dependencies struct {
	Authorizer Authorizer
	Domain     Domain
}

type jobEnvelope struct {
	Job Job `json:"job"`
}

type apiError struct {
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}
