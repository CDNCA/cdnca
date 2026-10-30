package controlupgrade

import (
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

const (
	ReasonEligible                   = "eligible"
	ReasonEntitlementUnavailable     = "entitlement_unavailable"
	ReasonEntitlementInvalid         = "entitlement_invalid"
	ReasonEntitlementStateDenied     = "entitlement_state_denied"
	ReasonEntitlementChannelMismatch = "entitlement_channel_mismatch"
	ReasonEntitlementVersionDenied   = "entitlement_version_denied"
	ReasonPlatformPolicyStale        = "platform_policy_stale"
	ReasonReleaseChannelDenied       = "release_channel_denied"
)

var (
	ErrInvalidInput          = errors.New("invalid control upgrade check input")
	ErrPermissionDenied      = errors.New("control upgrade check permission denied")
	ErrIdempotencyConflict   = errors.New("control upgrade check idempotency conflict")
	ErrRolloutNotFound       = errors.New("control upgrade rollout not found")
	ErrNodeNotFound          = errors.New("control upgrade node not found")
	ErrCohortIncompatible    = errors.New("control upgrade cohort incompatible")
	ErrResourceUnavailable   = errors.New("control upgrade resource unavailable")
	ErrGrantInvalid          = errors.New("control upgrade grant invalid")
	ErrExecutionInvalid      = errors.New("control upgrade execution invalid")
	ErrRuntimeUnavailable    = errors.New("control upgrade runtime unavailable")
	ErrLicenseUnavailable    = errors.New("control upgrade license unavailable")
	ErrLicenseOutcomeUnknown = errors.New("control upgrade license outcome unknown")
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type CheckRequest struct {
	Component      string `json:"component"`
	CurrentVersion string `json:"current_version"`
	Channel        string `json:"channel"`
	IdempotencyKey string `json:"-"`
	RequestID      string `json:"-"`
}

type EntitlementDecision struct {
	Serial     uint64 `json:"serial"`
	Channel    string `json:"channel"`
	MinVersion string `json:"min_version"`
	MaxVersion string `json:"max_version"`
}

type PolicyDecision struct {
	Source           string `json:"source"`
	TargetRevisionID string `json:"target_revision_id,omitempty"`
	Stale            bool   `json:"stale"`
}

type CheckResponse struct {
	Eligible       bool                 `json:"eligible"`
	Reason         string               `json:"reason"`
	Component      string               `json:"component"`
	CurrentVersion string               `json:"current_version"`
	Channel        string               `json:"channel"`
	Entitlement    *EntitlementDecision `json:"entitlement,omitempty"`
	Policy         PolicyDecision       `json:"policy"`
	Replayed       bool                 `json:"-"`
}

type CommandProfile struct {
	Platform      string                                     `json:"platform"`
	Architecture  string                                     `json:"architecture"`
	Compatibility entitlement.UpgradeExecutionCompatibility  `json:"compatibility"`
	Health        entitlement.UpgradeExecutionHealthPolicy   `json:"health"`
	Rollout       entitlement.UpgradeExecutionRolloutPolicy  `json:"rollout"`
	Rollback      entitlement.UpgradeExecutionRollbackPolicy `json:"rollback"`
}

type CreateRolloutBody struct {
	Schema            string   `json:"schema"`
	NodeIDs           []string `json:"node_ids"`
	CanaryNodeIDs     []string `json:"canary_node_ids"`
	BatchSize         int      `json:"batch_size"`
	AutomaticRollback bool     `json:"automatic_rollback"`
}

type CreateRolloutRequest struct {
	CreateRolloutBody
	IdempotencyKey string `json:"-"`
	RequestID      string `json:"-"`
}

type RolloutActionBody struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Reason           string `json:"reason"`
}

type RolloutActionRequest struct {
	RolloutActionBody
	PlanID         string `json:"-"`
	Operation      string `json:"-"`
	IdempotencyKey string `json:"-"`
	RequestID      string `json:"-"`
}

type ListRolloutsRequest struct {
	Page     int
	PageSize int
	State    PlanState
	NodeID   string
}

type RolloutBlocker struct {
	Code   PlanBlockerCode `json:"code"`
	NodeID string          `json:"node_id,omitempty"`
}

type RolloutSummary struct {
	ID                        string           `json:"id"`
	SchemaVersion             uint16           `json:"schema_version"`
	InstallationID            string           `json:"installation_id"`
	Component                 string           `json:"component"`
	CurrentVersion            string           `json:"current_version"`
	TargetVersion             string           `json:"target_version"`
	State                     PlanState        `json:"state"`
	Completion                PlanCompletion   `json:"completion"`
	Revision                  uint64           `json:"revision"`
	AutomaticRollback         bool             `json:"automatic_rollback"`
	ParentGrantID             string           `json:"parent_grant_id"`
	ArtifactID                string           `json:"artifact_id"`
	ArtifactSHA256            string           `json:"artifact_sha256"`
	ArtifactSizeBytes         int64            `json:"artifact_size_bytes"`
	RollbackArtifactID        string           `json:"rollback_artifact_id"`
	RollbackArtifactSHA256    string           `json:"rollback_artifact_sha256"`
	RollbackArtifactSizeBytes int64            `json:"rollback_artifact_size_bytes"`
	ActiveBatch               int              `json:"active_batch"`
	TotalNodes                int              `json:"total_nodes"`
	PendingNodes              int              `json:"pending_nodes"`
	DispatchedNodes           int              `json:"dispatched_nodes"`
	HealthyNodes              int              `json:"healthy_nodes"`
	FailedNodes               int              `json:"failed_nodes"`
	RolledBackNodes           int              `json:"rolled_back_nodes"`
	Blockers                  []RolloutBlocker `json:"blockers"`
	CreatedAt                 time.Time        `json:"created_at"`
	UpdatedAt                 time.Time        `json:"updated_at"`
}

type RolloutBatch struct {
	ID      string   `json:"id"`
	GroupID string   `json:"group_id"`
	Canary  bool     `json:"canary"`
	NodeIDs []string `json:"node_ids"`
}

type RolloutNode struct {
	NodeID           string        `json:"node_id"`
	AgentVersion     string        `json:"agent_version"`
	ProtocolVersion  uint32        `json:"protocol_version"`
	State            PlanNodeState `json:"state"`
	DispatchRevision uint64        `json:"dispatch_revision"`
}

type RolloutEvent struct {
	ID       string    `json:"id"`
	Revision uint64    `json:"revision"`
	From     PlanState `json:"from"`
	To       PlanState `json:"to"`
	Action   string    `json:"action"`
	Reason   string    `json:"reason"`
	BatchID  string    `json:"batch_id"`
	NodeID   string    `json:"node_id"`
}

type RolloutDetail struct {
	RolloutSummary
	Batches []RolloutBatch `json:"batches"`
	Nodes   []RolloutNode  `json:"nodes"`
	Events  []RolloutEvent `json:"events"`
	// EventTimes maps an event revision to when it was committed. It is read
	// only for the detail view and never takes part in replay or digests.
	EventTimes map[uint64]time.Time `json:"-"`
}

type ListRolloutsResponse struct {
	Data     []RolloutSummary `json:"data"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
	Total    int64            `json:"total"`
}
