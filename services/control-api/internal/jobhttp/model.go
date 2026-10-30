package jobhttp

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidRequest       = errors.New("invalid job query request")
	ErrPermissionDenied     = errors.New("job query permission denied")
	ErrScopeForbidden       = errors.New("job query scope forbidden")
	ErrNotFound             = errors.New("job not found")
	ErrStoreUnavailable     = errors.New("job store unavailable")
	ErrInvalidStoreResponse = errors.New("job store returned invalid facts")
	ErrResponseTooLarge     = errors.New("job query response too large")
	ErrIdempotencyConflict  = errors.New("job command idempotency conflict")
	ErrInvalidTransition    = errors.New("job command state transition is invalid")
	ErrRetriesExhausted     = errors.New("job command retries are exhausted")
	ErrRevisionConflict     = errors.New("job command revision is stale")
	// ErrProducerCommand: the job's producer owns cancel/retry (its own
	// projection must move with the job); the generic command refuses it.
	ErrProducerCommand = errors.New("job command belongs to the producer")
)

const (
	PermissionRead      = "jobs.read"
	PermissionReadAll   = "jobs.read_all"
	PermissionManage    = "jobs.manage"
	PermissionManageAll = "jobs.manage_all"
	PermissionAdmin     = "platform.admin"
)

type Audience string

const (
	AudiencePlatform Audience = "platform"
	AudienceTenant   Audience = "tenant"
)

type ScopeKind string

const (
	ScopePlatform ScopeKind = "platform"
	ScopeTenant   ScopeKind = "tenant"
)

type State string

const (
	StateQueued        State = "queued"
	StateRunning       State = "running"
	StateSucceeded     State = "succeeded"
	StatePartialFailed State = "partial_failed"
	StateFailed        State = "failed"
	StateCancelled     State = "cancelled"
)

type AttemptState string

const (
	AttemptRunning       AttemptState = "running"
	AttemptSucceeded     AttemptState = "succeeded"
	AttemptPartialFailed AttemptState = "partial_failed"
	AttemptFailed        AttemptState = "failed"
	AttemptCancelled     AttemptState = "cancelled"
	AttemptLeaseExpired  AttemptState = "lease_expired"
)

type ResultState string

const (
	ResultPending   ResultState = "pending"
	ResultSucceeded ResultState = "succeeded"
	ResultFailed    ResultState = "failed"
	ResultCancelled ResultState = "cancelled"
)

type Principal struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   ScopeKind
	Permissions map[string]struct{}
	// apiKey 为本次请求的 API 密钥凭据（Bearer 会话为 nil），命令事务内据此复核。
	// 用指针保存：fmt 打印嵌套指针只输出地址，原凭据不会进日志。
	apiKey *apiKeyCredential
	// session 为 Bearer 会话原凭据，供生产者命令（缓存模块）在其事务内复核会话；
	// 同样用指针保存，fmt 只输出地址。
	session *sessionCredential
}

type sessionCredential struct {
	raw string
}

// WithSessionCredential 绑定认证时使用的 Bearer 会话凭据（fix-cacheflow2：缓存任务的
// 取消/重试转给缓存模块执行，缓存模块按同一会话复核权限）。
func (principal Principal) WithSessionCredential(raw string) Principal {
	principal.session = &sessionCredential{raw: raw}
	return principal
}

// SessionToken 返回 Bearer 会话原凭据；API 密钥或未绑定时为空。
func (principal Principal) SessionToken() string {
	if principal.session == nil {
		return ""
	}
	return principal.session.raw
}

type apiKeyCredential struct {
	keyID uuid.UUID
	raw   string
}

// WithAPIKeyCredential 绑定认证时使用的 API 密钥（api_keys.id 与原凭据），
// 命令事务内会用 iamlock.AuthorizeAPIKey 复核，挡住认证后被吊销或缩权的密钥（API-JOBS-02）。
func (principal Principal) WithAPIKeyCredential(keyID uuid.UUID, raw string) Principal {
	principal.apiKey = &apiKeyCredential{keyID: keyID, raw: raw}
	return principal
}

// APIKeyCredential 返回本次请求的 API 密钥（api_keys.id 与原凭据）；Bearer 会话为 uuid.Nil 与空串。
// 供生产者命令（缓存模块）在其事务内按“密钥范围 ∩ 持有人当前权限”复核（fix-cacheflow3 §1）。
func (principal Principal) APIKeyCredential() (uuid.UUID, string) {
	if principal.apiKey == nil {
		return uuid.Nil, ""
	}
	return principal.apiKey.keyID, principal.apiKey.raw
}

func (principal Principal) HasPermission(permission string) bool {
	_, ok := principal.Permissions[permission]
	return ok
}

type ReadScope struct {
	Kind ScopeKind
	ID   uuid.UUID
}

type ListRequest struct {
	Audience Audience
	TenantID *uuid.UUID
	TaskID   *uuid.UUID
	States   []State
	Kind     string
	Resource string
	From     time.Time
	To       time.Time
	Limit    int
	Cursor   string
	Page     int
}

type ListQuery struct {
	TenantID     *uuid.UUID
	TaskID       *uuid.UUID
	States       []State
	Kind         string
	Resource     string
	From         time.Time
	To           time.Time
	AfterCreated *time.Time
	AfterTaskID  *uuid.UUID
	Limit        int
	Offset       int64
}

type ChildPageRequest struct {
	Audience Audience
	TaskID   uuid.UUID
	Limit    int
	Cursor   string
}

type AttemptQuery struct {
	AfterAttempt *uint32
	Limit        int
}

type ResultQuery struct {
	AfterOrdinal *int
	Limit        int
}

type ReceiptQuery struct {
	AfterAttempt *uint32
	AfterOrdinal *int
	Limit        int
}

type DeadLetterQuery struct {
	AfterAttempt *uint32
	Limit        int
}

type RelatedResource struct {
	Reference string `json:"reference"`
}

type Progress struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
	Pending   int `json:"pending"`
}

type Job struct {
	TaskID          uuid.UUID       `json:"task_id"`
	TenantID        uuid.UUID       `json:"tenant_id"`
	Kind            string          `json:"kind"`
	RelatedResource RelatedResource `json:"related_resource"`
	RequestID       string          `json:"request_id"`
	TraceID         string          `json:"trace_id,omitempty"`
	Status          State           `json:"status"`
	Attempt         uint32          `json:"attempt"`
	MaxAttempts     uint32          `json:"max_attempts"`
	Progress        Progress        `json:"progress"`
	FailureCode     string          `json:"failure_code,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	Revision        string          `json:"revision"`
	taskMetadata    *TaskMetadata
	// resourceMatchedByNode is set by list readers when a resource filter
	// matched one of the job's item nodes rather than its subject.
	resourceMatchedByNode bool
}

type Attempt struct {
	Number          uint32       `json:"number"`
	Status          AttemptState `json:"status"`
	StartedAt       time.Time    `json:"started_at"`
	LastHeartbeatAt time.Time    `json:"last_heartbeat_at"`
	LeaseExpiresAt  time.Time    `json:"lease_expires_at"`
	CompletedAt     *time.Time   `json:"completed_at,omitempty"`
	FailureCode     string       `json:"failure_code,omitempty"`
}

type ItemResult struct {
	Ordinal     int         `json:"ordinal"`
	ItemID      string      `json:"item_id"`
	NodeID      *uuid.UUID  `json:"node_id,omitempty"`
	Status      ResultState `json:"status"`
	Attempt     uint32      `json:"attempt"`
	Sequence    uint64      `json:"sequence"`
	FailureCode string      `json:"failure_code,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
	// StartedAt is the start of the attempt that settled this item; omitted while pending.
	StartedAt *time.Time `json:"started_at,omitempty"`
	// FailureCount counts recorded failed settlement receipts for this item.
	FailureCount int `json:"failure_count"`
}

type SettlementReceipt struct {
	Ordinal     int         `json:"ordinal"`
	ItemID      string      `json:"item_id"`
	NodeID      *uuid.UUID  `json:"node_id,omitempty"`
	Status      ResultState `json:"status"`
	Attempt     uint32      `json:"attempt"`
	Sequence    uint64      `json:"sequence"`
	FailureCode string      `json:"failure_code,omitempty"`
	Source      string      `json:"source"`
	ReportedAt  time.Time   `json:"reported_at"`
}

type DeadLetter struct {
	Attempt         uint32    `json:"attempt"`
	ReasonCode      string    `json:"reason_code"`
	FailedItemCount int       `json:"failed_item_count"`
	Source          string    `json:"source"`
	CreatedAt       time.Time `json:"created_at"`
}

type PageMeta struct {
	NextCursor  string `json:"next_cursor,omitempty"`
	Number      int    `json:"number,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Total       *int64 `json:"total,omitempty"`
	TotalPages  *int64 `json:"total_pages,omitempty"`
	Consistency string `json:"consistency,omitempty"`
}

type QueryMeta struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type JobPage struct {
	Data         []Job           `json:"data"`
	Page         PageMeta        `json:"page"`
	Query        QueryMeta       `json:"query"`
	TaskMetadata *[]TaskMetadata `json:"task_metadata,omitempty"`
}

type AttemptPage struct {
	Data []Attempt `json:"data"`
	Page PageMeta  `json:"page"`
}

type ResultPage struct {
	Data []ItemResult `json:"data"`
	Page PageMeta     `json:"page"`
}

type ReceiptPage struct {
	Data []SettlementReceipt `json:"data"`
	Page PageMeta            `json:"page"`
}

type DeadLetterPage struct {
	Data []DeadLetter `json:"data"`
	Page PageMeta     `json:"page"`
}

type Reader interface {
	List(context.Context, ReadScope, ListQuery) ([]Job, error)
	Get(context.Context, ReadScope, uuid.UUID) (Job, error)
	Attempts(context.Context, ReadScope, uuid.UUID, AttemptQuery) ([]Attempt, error)
	Results(context.Context, ReadScope, uuid.UUID, ResultQuery) ([]ItemResult, error)
}

type NumberedPageReader interface {
	ListNumberedPage(context.Context, ReadScope, ListQuery) ([]Job, int64, error)
}

type SettlementReader interface {
	Receipts(context.Context, ReadScope, uuid.UUID, ReceiptQuery) ([]SettlementReceipt, error)
	DeadLetters(context.Context, ReadScope, uuid.UUID, DeadLetterQuery) ([]DeadLetter, error)
}

type CommandOperation string

const (
	CommandCancel CommandOperation = "cancel"
	CommandRetry  CommandOperation = "retry"
	CommandReplay CommandOperation = "replay"
)

type CommandRequest struct {
	Audience         Audience
	TaskID           uuid.UUID
	Operation        CommandOperation
	IdempotencyKey   string
	ExpectedRevision string
}

type CommandDigest [32]byte

type CommandInput struct {
	Principal        Principal
	Audience         Audience
	TaskID           uuid.UUID
	Operation        CommandOperation
	IdempotencyKey   string
	Digest           CommandDigest
	RequestID        string
	ExpectedRevision string
}

type CommandResult struct {
	Data     Job  `json:"data"`
	Replayed bool `json:"replayed"`
}

type CommandStore interface {
	Execute(context.Context, CommandInput) (CommandResult, error)
}
