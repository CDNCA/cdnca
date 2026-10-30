package nodeisolation

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput     = errors.New("invalid node isolation input")
	ErrConflict         = errors.New("node isolation report conflict")
	ErrNotFound         = errors.New("node isolation node not found")
	ErrOutcomeUncertain = errors.New("node isolation outcome uncertain")
)

type Status string

const (
	StatusActive   Status = "active"
	StatusIsolated Status = "isolated"
)

type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeUnknown   Outcome = "unknown"
)

const (
	ReasonHealthy          = "healthy"
	ReasonFailurePending   = "sync_failure_pending"
	ReasonFailureThreshold = "sync_failure_threshold"
	ReasonOutcomeUnknown   = "sync_outcome_unknown"
	ReasonIdentityMismatch = "active_config_identity_mismatch"
	ReasonEvidenceStale    = "health_evidence_stale"
	ReasonRecoveryPending  = "recovery_confirmation_pending"
	ReasonRecovered        = "recovered"
	ReasonOutcomeUncertain = "operation_outcome_uncertain"

	AuditSyncResultRecorded = "node_config_sync_result_recorded"
	AuditNodeIsolated       = "node_config_sync_isolated"
	AuditNodeRecovered      = "node_config_sync_recovered"
)

type EffectKind string

const (
	EffectAudit         EffectKind = "audit"
	EffectAlertOpened   EffectKind = "alert_opened"
	EffectAlertResolved EffectKind = "alert_resolved"
)

type ConfigIdentity struct {
	Schema          uint32    `json:"schema"`
	ConfigVersionID uuid.UUID `json:"config_version_id"`
	ArtifactSHA256  [32]byte  `json:"artifact_sha256"`
}

type HealthEvidence struct {
	SessionEpoch uint64         `json:"session_epoch"`
	Sequence     uint64         `json:"sequence"`
	ObservedAt   time.Time      `json:"observed_at"`
	Active       ConfigIdentity `json:"active"`
}

type Policy struct {
	FailureThreshold  uint32
	RecoveryThreshold uint32
	MaxEvidenceAge    time.Duration
}

type SyncResult struct {
	ScopeID   uuid.UUID       `json:"scope_id"`
	NodeID    uuid.UUID       `json:"node_id"`
	ReportID  uuid.UUID       `json:"report_id"`
	Desired   ConfigIdentity  `json:"desired"`
	Outcome   Outcome         `json:"outcome"`
	ErrorCode string          `json:"error_code,omitempty"`
	Health    *HealthEvidence `json:"health,omitempty"`
}

type State struct {
	ScopeID             uuid.UUID      `json:"scope_id"`
	NodeID              uuid.UUID      `json:"node_id"`
	Status              Status         `json:"status"`
	Desired             ConfigIdentity `json:"desired"`
	ConsecutiveFailures uint32         `json:"consecutive_failures"`
	ConsecutiveHealthy  uint32         `json:"consecutive_healthy"`
	LastSessionEpoch    uint64         `json:"last_session_epoch"`
	LastHealthSequence  uint64         `json:"last_health_sequence"`
	LastReportID        uuid.UUID      `json:"last_report_id"`
	LastOutcome         Outcome        `json:"last_outcome"`
	LastErrorCode       string         `json:"last_error_code,omitempty"`
	ReasonCode          string         `json:"reason_code"`
	Revision            uint64         `json:"revision"`
	IsolatedAt          *time.Time     `json:"isolated_at,omitempty"`
	RecoveredAt         *time.Time     `json:"recovered_at,omitempty"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

type Effect struct {
	Kind      EffectKind `json:"kind"`
	Code      string     `json:"code"`
	DedupeKey string     `json:"dedupe_key"`
}

type Result struct {
	State              State    `json:"state"`
	PublicationAllowed bool     `json:"publication_allowed"`
	ReasonCode         string   `json:"reason_code"`
	Effects            []Effect `json:"effects,omitempty"`
	Replay             bool     `json:"replay"`
}

type ApplyResult = Result

type ApplyCommand struct {
	Result SyncResult
	Policy Policy
	Now    time.Time
	Digest [32]byte
}

type Repository interface {
	Apply(context.Context, ApplyCommand) (ApplyResult, error)
	List(context.Context, uuid.UUID, []uuid.UUID) (map[uuid.UUID]State, error)
}

type PublicationDecision struct {
	NodeID     uuid.UUID `json:"node_id"`
	Allowed    bool      `json:"allowed"`
	Status     Status    `json:"status"`
	ReasonCode string    `json:"reason_code"`
}

type PublicationPlan struct {
	EligibleNodeIDs []uuid.UUID           `json:"eligible_node_ids"`
	IsolatedNodeIDs []uuid.UUID           `json:"isolated_node_ids"`
	Decisions       []PublicationDecision `json:"decisions"`
}
