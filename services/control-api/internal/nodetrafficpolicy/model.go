package nodetrafficpolicy

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

func PolicyID(scopeID, nodeID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca.node-traffic-policy/v1:"+strings.ToLower(scopeID.String())+":"+strings.ToLower(nodeID.String())))
}

const (
	maxPostgresBigint = uint64(1<<63 - 1)

	ScopeKindPlatform = "platform"
	ScopeKindTenant   = "tenant"

	PermissionRead   = "nodes.read"
	PermissionManage = "nodes.manage"

	NodeStateActive   = "active"
	NodeStateDisabled = "disabled"
	NodeStateRetired  = "retired"

	OverrideNone          = "none"
	OverrideForceEnabled  = "force_enabled"
	OverrideForceDisabled = "force_disabled"

	ReasonWithinPolicy        = "within_policy"
	ReasonMonthlyLimitReached = "monthly_limit_reached"
	ReasonScheduledWindow     = "scheduled_window"
	ReasonManualForceEnabled  = "manual_force_enabled"
	ReasonManualForceDisabled = "manual_force_disabled"
	ReasonAdminStateProtected = "admin_state_protected"
	ReasonPeriodReset         = "period_reset"
	ReasonPolicyRecovered     = "policy_recovered"

	SyncTaskQueued    = "queued"
	SyncTaskRunning   = "running"
	SyncTaskSucceeded = "succeeded"
	SyncTaskFailed    = "failed"
)

var (
	ErrInvalidInput        = errors.New("invalid node traffic policy input")
	ErrInvalidConfig       = errors.New("invalid node traffic policy service configuration")
	ErrUnauthenticated     = errors.New("node traffic policy authentication required")
	ErrPermissionDenied    = errors.New("node traffic policy permission denied")
	ErrNotFound            = errors.New("node traffic policy not found")
	ErrRevisionConflict    = errors.New("node traffic policy revision conflict")
	ErrIdempotencyConflict = errors.New("node traffic policy idempotency conflict")
	ErrUsageUnavailable    = errors.New("node traffic usage evidence unavailable")
	ErrConfigUnavailable   = errors.New("node configuration version unavailable")
	ErrUnavailable         = errors.New("node traffic policy unavailable")
)

type Actor struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	Permissions []string
}

type ManualOverride struct {
	Mode      string     `json:"mode"`
	Revision  int64      `json:"revision"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type ScheduleWindow struct {
	Weekday     time.Weekday `json:"weekday"`
	StartMinute int          `json:"start_minute"`
	EndMinute   int          `json:"end_minute"`
}

type Policy struct {
	ID                uuid.UUID        `json:"id"`
	ScopeID           uuid.UUID        `json:"scope_id"`
	NodeID            uuid.UUID        `json:"node_id"`
	MonthlyLimitBytes uint64           `json:"monthly_limit_bytes"`
	Timezone          string           `json:"timezone"`
	Windows           []ScheduleWindow `json:"windows"`
	Override          ManualOverride   `json:"manual_override"`
	Revision          int64            `json:"revision"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`
}

type Period struct {
	Key   string    `json:"key"`
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type UsageQuery struct {
	ScopeID    uuid.UUID
	NodeID     uuid.UUID
	Period     Period
	SnapshotAt time.Time
}

type UsageEvidence struct {
	Bytes            uint64    `json:"bytes"`
	SnapshotAt       time.Time `json:"snapshot_at"`
	FinalizedThrough time.Time `json:"finalized_through"`
	SourceDigest     string    `json:"source_digest"`
}

type EvaluationSnapshot struct {
	PeriodKey        string `json:"period_key"`
	Suppressed       bool   `json:"suppressed"`
	ReasonCode       string `json:"reason_code"`
	OverrideRevision int64  `json:"override_revision"`
}

type EvaluationDecision struct {
	PeriodKey              string    `json:"period_key"`
	PeriodStart            time.Time `json:"period_start"`
	PeriodEnd              time.Time `json:"period_end"`
	UsageBytes             uint64    `json:"usage_bytes"`
	MonthlyLimitBytes      uint64    `json:"monthly_limit_bytes"`
	Suppressed             bool      `json:"suppressed"`
	SyncRequired           bool      `json:"sync_required"`
	ReasonCode             string    `json:"reason_code"`
	OverrideRevision       int64     `json:"override_revision"`
	EvaluatedAt            time.Time `json:"evaluated_at"`
	SourceSnapshotAt       time.Time `json:"source_snapshot_at"`
	SourceFinalizedThrough time.Time `json:"source_finalized_through"`
	SourceDigest           string    `json:"source_digest"`
}

type EvaluationInput struct {
	Policy     Policy
	Now        time.Time
	Usage      UsageEvidence
	AdminState string
	Previous   *EvaluationSnapshot
}

type SyncTask struct {
	ID              uuid.UUID  `json:"id"`
	ScopeID         uuid.UUID  `json:"scope_id"`
	NodeID          uuid.UUID  `json:"node_id"`
	ConfigVersionID uuid.UUID  `json:"config_version_id"`
	Status          string     `json:"status"`
	ErrorCode       *string    `json:"error_code"`
	RolloutID       *uuid.UUID `json:"rollout_id"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type PolicyState struct {
	Policy                 Policy              `json:"policy"`
	AdminState             string              `json:"admin_state"`
	CurrentConfigVersionID *uuid.UUID          `json:"current_config_version_id"`
	LastEvaluation         *EvaluationSnapshot `json:"last_evaluation"`
}

type PutRequest struct {
	Policy           Policy
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type WriteResult struct {
	State    PolicyState `json:"state"`
	Replayed bool        `json:"replayed"`
}

type EvaluateRequest struct {
	ScopeID        uuid.UUID
	NodeID         uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type ApplyEvaluationRequest struct {
	ScopeID        uuid.UUID
	NodeID         uuid.UUID
	ActorUserID    uuid.UUID
	AdminState     string
	PolicyRevision int64
	Decision       EvaluationDecision
	SyncTask       *SyncTask
	IdempotencyKey string
	RequestID      string
}

type EvaluationRecord struct {
	ID       uuid.UUID          `json:"id"`
	ScopeID  uuid.UUID          `json:"scope_id"`
	NodeID   uuid.UUID          `json:"node_id"`
	Decision EvaluationDecision `json:"decision"`
	SyncTask *SyncTask          `json:"sync_task"`
	Replayed bool               `json:"replayed"`
}
