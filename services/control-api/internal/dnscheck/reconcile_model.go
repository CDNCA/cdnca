package dnscheck

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrIdempotencyConflict      = errors.New("dns reconcile idempotency conflict")
	ErrProviderRevisionConflict = errors.New("dns provider revision conflict")
	ErrTaskNotFound             = errors.New("dns reconcile task not found")
	ErrCommitNotReady           = errors.New("dns reconcile commit not ready")
)

type ProviderErrorClass string

const (
	ProviderErrorNone             ProviderErrorClass = ""
	ProviderErrorTransient        ProviderErrorClass = "transient"
	ProviderErrorPermanent        ProviderErrorClass = "permanent"
	ProviderErrorRevisionConflict ProviderErrorClass = "revision_conflict"
	ProviderErrorCancelled        ProviderErrorClass = "cancelled"
	ProviderErrorTimeout          ProviderErrorClass = "timeout"
)

type ProviderError struct {
	Class             ProviderErrorClass
	Code              string
	RetryAfter        time.Duration
	ProviderRequestID string
}

func (e *ProviderError) Error() string {
	if e == nil || e.Code == "" {
		return "dns provider operation failed"
	}
	return "dns provider operation failed: " + e.Code
}

type ProviderRevisionRequest struct {
	TenantID uuid.UUID
	SiteID   uuid.UUID
	ZoneID   uuid.UUID
}

type ProviderMutation struct {
	ClientRequestID  string
	TenantID         uuid.UUID
	SiteID           uuid.UUID
	ZoneID           uuid.UUID
	ExpectedRevision int64
	Operation        ProviderOperation
}

type ProviderMutationResult struct {
	ProviderRequestID string
	RecordID          string
	Revision          int64
}

type ProviderAdapter interface {
	CurrentRevision(context.Context, ProviderRevisionRequest) (int64, error)
	// Mutate must replay the original result for a repeated ClientRequestID
	// before evaluating ExpectedRevision. Durable recovery relies on this when
	// a provider accepted a mutation but its local checkpoint was lost.
	Mutate(context.Context, ProviderMutation) (ProviderMutationResult, error)
}

type TaskStatus string

const (
	TaskDryRun        TaskStatus = "dry_run"
	TaskApplying      TaskStatus = "applying"
	TaskPropagating   TaskStatus = "propagating"
	TaskReadyToCommit TaskStatus = "ready_to_commit"
	TaskCommitted     TaskStatus = "committed"
	TaskFailed        TaskStatus = "failed"
	TaskCancelled     TaskStatus = "cancelled"
	TaskTimedOut      TaskStatus = "timed_out"
	TaskCommitFailed  TaskStatus = "commit_failed"
)

type OperationStatus string

const (
	OperationPlanned          OperationStatus = "planned"
	OperationDeferred         OperationStatus = "deferred_until_commit"
	OperationRunning          OperationStatus = "running"
	OperationSucceeded        OperationStatus = "succeeded"
	OperationTransientFailed  OperationStatus = "transient_failed"
	OperationPermanentFailed  OperationStatus = "permanent_failed"
	OperationRevisionConflict OperationStatus = "revision_conflict"
	OperationCancelled        OperationStatus = "cancelled"
	OperationSkipped          OperationStatus = "skipped"
)

type OperationResult struct {
	SourceSequence    int
	Operation         ProviderOperation
	ClientRequestID   string
	ProviderRequestID string
	ProviderRecordID  string
	ProviderRevision  int64
	Status            OperationStatus
	Attempts          int
	RetryAfter        time.Duration
	ErrorClass        ProviderErrorClass
	ErrorCode         string
	ReportSequence    uint64
}

type ProviderReport struct {
	ClientRequestID   string
	ProviderRequestID string
	ProviderRecordID  string
	ProviderRevision  int64
	Status            OperationStatus
	ErrorClass        ProviderErrorClass
	ErrorCode         string
	RetryAfter        time.Duration
	Sequence          uint64
}

type PropagationAttempt struct {
	Number                int
	CheckedAt             time.Time
	Status                Classification
	ConsecutiveHealthy    int
	DependencyUnavailable bool
}

type ReconcileRequest struct {
	IdempotencyKey string
	Check          CheckRequest
}

type CommitRequest struct {
	TenantID       uuid.UUID
	SiteID         uuid.UUID
	IdempotencyKey string
	PayloadDigest  string
}

type ProviderReportRequest struct {
	TenantID       uuid.UUID
	SiteID         uuid.UUID
	IdempotencyKey string
	PayloadDigest  string
	Report         ProviderReport
}

type ReconcileResult struct {
	TenantID         uuid.UUID
	SiteID           uuid.UUID
	ZoneID           uuid.UUID
	PayloadDigest    string
	Plan             RepairPlan
	Status           TaskStatus
	Replayed         bool
	StartedAt        time.Time
	UpdatedAt        time.Time
	ReadyAt          *time.Time
	InitialRevision  int64
	ProviderRevision int64
	Operations       []OperationResult
	DeferredDeletes  []OperationResult
	CompensationPlan []ProviderOperation
	Propagation      []PropagationAttempt
	LastCheck        *CheckResult
	ErrorClass       ProviderErrorClass
	ErrorCode        string
}

type ReconcilerConfig struct {
	Checker             *Checker
	Provider            ProviderAdapter
	ProviderAttempts    int
	ProviderTimeout     time.Duration
	PollAttempts        int
	RequiredConsecutive int
	InitialBackoff      time.Duration
	MaximumBackoff      time.Duration
	OverallTimeout      time.Duration
	JitterFraction      float64
	Now                 func() time.Time
	Sleep               func(context.Context, time.Duration) error
	Random              func() float64
}
