package diskguard

import (
	"context"
	"errors"
	"time"
)

const (
	SchemaVersion       = 1
	ConfigSchemaVersion = "cdnca.edge.diskguard/v1"
)

var (
	ErrInvalidConfig  = errors.New("invalid disk guard config")
	ErrAlreadyRunning = errors.New("disk guard already running")
	ErrEvaluation     = errors.New("disk guard evaluation failed")
)

type DirectoryKind string

const (
	DirectoryRotatedLogs DirectoryKind = "rotated_logs"
	DirectoryCacheTemp   DirectoryKind = "cache_temp"
)

type ManagedDirectory struct {
	ID            string
	Path          string
	Kind          DirectoryKind
	Patterns      []string
	ActiveNames   []string
	MinimumAge    time.Duration
	MinimumRemain int
}

type Config struct {
	SchemaVersion     string
	ConfigID          string
	Revision          uint64
	LockPath          string
	LowWatermark      uint16
	HighWatermark     uint16
	EvaluationPeriod  time.Duration
	MaxDeletedFiles   int
	MaxAllocatedBytes uint64
	DryRun            bool
	Directories       []ManagedDirectory
	ProtectedPaths    []string
}

type EventCode string

const (
	EventEvaluationStarted    EventCode = "disk_guard_evaluation_started"
	EventPressureEntered      EventCode = "disk_guard_pressure_entered"
	EventPressureRecovered    EventCode = "disk_guard_pressure_recovered"
	EventCandidateDeleted     EventCode = "disk_guard_candidate_deleted"
	EventCandidateWouldDelete EventCode = "disk_guard_candidate_would_delete"
	EventEvaluationFailed     EventCode = "disk_guard_evaluation_failed"
	EventEvaluationCompleted  EventCode = "disk_guard_evaluation_completed"
)

type FailureReason string

const (
	FailureNone             FailureReason = ""
	FailureLockHeld         FailureReason = "lock_held"
	FailureLockUnsafe       FailureReason = "lock_unsafe"
	FailureCancelled        FailureReason = "cancelled"
	FailureDirectoryUnsafe  FailureReason = "directory_unsafe"
	FailureUsageUnavailable FailureReason = "usage_unavailable"
	FailureScanFailed       FailureReason = "scan_failed"
	FailureCandidateChanged FailureReason = "candidate_changed"
	FailureDeleteFailed     FailureReason = "delete_failed"
)

type Event struct {
	SchemaVersion   int           `json:"schema_version"`
	Code            EventCode     `json:"code"`
	OccurredAt      time.Time     `json:"occurred_at"`
	ConfigID        string        `json:"config_id"`
	ConfigRevision  uint64        `json:"config_revision"`
	DirectoryID     string        `json:"directory_id,omitempty"`
	FileName        string        `json:"file_name,omitempty"`
	Category        DirectoryKind `json:"category,omitempty"`
	UsedBasisPoints uint16        `json:"used_basis_points,omitempty"`
	AllocatedBytes  uint64        `json:"allocated_bytes,omitempty"`
	DryRun          bool          `json:"dry_run"`
	FailureReason   FailureReason `json:"failure_reason,omitempty"`
}

type DirectoryMetric struct {
	DirectoryID     string `json:"directory_id"`
	UsedBasisPoints uint16 `json:"used_basis_points"`
	Pressure        bool   `json:"pressure"`
}

type Metrics struct {
	SchemaVersion         int               `json:"schema_version"`
	ObservedAt            time.Time         `json:"observed_at"`
	ConfigID              string            `json:"config_id"`
	ConfigRevision        uint64            `json:"config_revision"`
	DryRun                bool              `json:"dry_run"`
	Healthy               bool              `json:"healthy"`
	FailureReason         FailureReason     `json:"failure_reason,omitempty"`
	EvaluationsTotal      uint64            `json:"evaluations_total"`
	EvaluationFailures    uint64            `json:"evaluation_failures_total"`
	DeletedFilesTotal     uint64            `json:"deleted_files_total"`
	DeletedBytesTotal     uint64            `json:"deleted_allocated_bytes_total"`
	RoundCandidateFiles   int               `json:"round_candidate_files"`
	RoundDeletedFiles     int               `json:"round_deleted_files"`
	RoundDeletedBytes     uint64            `json:"round_deleted_allocated_bytes"`
	RoundWouldDeleteFiles int               `json:"round_would_delete_files"`
	RoundWouldDeleteBytes uint64            `json:"round_would_delete_allocated_bytes"`
	RoundProtectedFiles   int               `json:"round_protected_files"`
	RoundUnsafeFiles      int               `json:"round_unsafe_files"`
	RoundBudgetSkipped    int               `json:"round_budget_skipped"`
	Directories           []DirectoryMetric `json:"directories"`
}

type Report struct {
	Metrics Metrics `json:"metrics"`
	Events  []Event `json:"events"`
}

type EventSink interface {
	RecordDiskGuardEvent(context.Context, Event)
}

type Options struct {
	EventSink EventSink
	// MaxScanEntries may lower the built-in scan cap; zero uses the safe default.
	MaxScanEntries int
}
