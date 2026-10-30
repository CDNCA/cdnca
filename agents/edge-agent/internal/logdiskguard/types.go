package logdiskguard

import (
	"context"
	"errors"
	"time"
)

const (
	SchemaVersion       = 1
	ConfigSchemaVersion = "cdnca.edge.logdiskguard/v1"
)

var (
	ErrInvalidConfig  = errors.New("invalid log disk guard config")
	ErrAlreadyRunning = errors.New("log disk guard already running")
	ErrUnsafePath     = errors.New("unsafe log disk guard path")
	ErrCorruptState   = errors.New("corrupt log disk guard state")
)

type Config struct {
	Enabled          bool
	SchemaVersion    string
	ConfigID         string
	Revision         uint64
	SpoolRoot        string
	StateRoot        string
	LockPath         string
	LowWatermark     uint16
	HighWatermark    uint16
	MinimumFreeBytes uint64
	MinimumAge       time.Duration
	EvaluationPeriod time.Duration
	MaxRoundDuration time.Duration
	MaxDeletedFiles  int
	MaxDeletedBytes  uint64
	DryRun           bool
}

type Usage struct {
	TotalBytes     uint64
	AvailableBytes uint64
}

type ReasonCode string

const (
	ReasonDisabled              ReasonCode = "disabled"
	ReasonHealthy               ReasonCode = "healthy"
	ReasonPressureHighWatermark ReasonCode = "pressure_high_watermark"
	ReasonPressureMinimumFree   ReasonCode = "pressure_minimum_free"
	ReasonCleanupCompleted      ReasonCode = "cleanup_completed"
	ReasonBudgetExhausted       ReasonCode = "round_budget_exhausted"
	ReasonLockHeld              ReasonCode = "lock_held"
	ReasonUnsafePath            ReasonCode = "unsafe_path"
	ReasonCorruptState          ReasonCode = "corrupt_state"
	ReasonUsageUnavailable      ReasonCode = "usage_unavailable"
	ReasonDeleteFailed          ReasonCode = "delete_failed"
	ReasonCancelled             ReasonCode = "cancelled"
)

type Event struct {
	SchemaVersion   int        `json:"schema_version"`
	OccurredAt      time.Time  `json:"occurred_at"`
	ConfigID        string     `json:"config_id"`
	ConfigRevision  uint64     `json:"config_revision"`
	ReasonCode      ReasonCode `json:"reason_code"`
	UsedBasisPoints uint16     `json:"used_basis_points,omitempty"`
	AvailableBytes  uint64     `json:"available_bytes,omitempty"`
	FileName        string     `json:"file_name,omitempty"`
	DryRun          bool       `json:"dry_run"`
}

type EventSink interface {
	RecordLogDiskGuardEvent(context.Context, Event)
}

type Metrics struct {
	SchemaVersion         int        `json:"schema_version"`
	ObservedAt            time.Time  `json:"observed_at"`
	ConfigID              string     `json:"config_id"`
	ConfigRevision        uint64     `json:"config_revision"`
	ReasonCode            ReasonCode `json:"reason_code"`
	Healthy               bool       `json:"healthy"`
	Pressure              bool       `json:"pressure"`
	DryRun                bool       `json:"dry_run"`
	UsedBasisPoints       uint16     `json:"used_basis_points"`
	AvailableBytes        uint64     `json:"available_bytes"`
	EvaluationsTotal      uint64     `json:"evaluations_total"`
	EvaluationFailures    uint64     `json:"evaluation_failures_total"`
	DeletedFilesTotal     uint64     `json:"deleted_files_total"`
	DeletedBytesTotal     uint64     `json:"deleted_bytes_total"`
	RecoveredFilesTotal   uint64     `json:"recovered_files_total"`
	RoundCandidateFiles   int        `json:"round_candidate_files"`
	RoundDeletedFiles     int        `json:"round_deleted_files"`
	RoundDeletedBytes     uint64     `json:"round_deleted_bytes"`
	RoundWouldDeleteFiles int        `json:"round_would_delete_files"`
	RoundBudgetSkipped    int        `json:"round_budget_skipped"`
	RoundProtectedFiles   int        `json:"round_protected_files"`
	RoundRecoveredFiles   int        `json:"round_recovered_files"`
}

type Report struct {
	Metrics Metrics `json:"metrics"`
	Events  []Event `json:"events"`
}

type testHooks struct {
	afterQuarantine func() error
}

type Options struct {
	Now       func() time.Time
	Usage     func(string) (Usage, error)
	EventSink EventSink
	hooks     testHooks
}
