package ja4block

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	ErrInvalidConfiguration  = errors.New("JA4 block configuration invalid")
	ErrInvalidInput          = errors.New("JA4 block input invalid")
	ErrPermissionDenied      = errors.New("JA4 block permission denied")
	ErrSnapshotStale         = errors.New("JA4 ranking snapshot stale")
	ErrSnapshotExpired       = errors.New("JA4 ranking snapshot expired")
	ErrScopeConflict         = errors.New("JA4 block scope conflict")
	ErrRevisionConflict      = errors.New("JA4 block revision conflict")
	ErrIdempotencyConflict   = errors.New("JA4 block idempotency conflict")
	ErrNotFound              = errors.New("JA4 block workflow not found")
	ErrClaimLost             = errors.New("JA4 block workflow claim lost")
	ErrStoreUnavailable      = errors.New("JA4 block store unavailable")
	ErrDependencyUnavailable = errors.New("JA4 block dependency unavailable")
)

type Phase string

const (
	PhaseQueued      Phase = "queued"
	PhasePolicyReady Phase = "policy_ready"
	PhaseEdgePending Phase = "edge_pending"
	PhaseActive      Phase = "active"
	PhaseFailed      Phase = "failed"
	PhaseExpired     Phase = "expired"

	ActionApplyPolicy    = "apply_policy"
	ActionPublishBinding = "publish_binding"
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	SessionID uuid.UUID
}

type SubmitInput struct {
	TenantScopeID    uuid.UUID
	SiteID           uuid.UUID
	JA4              string
	SnapshotAt       time.Time
	Duration         time.Duration
	Reason           string
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	SessionID        uuid.UUID
	StepUpEvidenceID uuid.UUID
	StepUpVerifiedAt time.Time
}

type AuthorityRequest struct {
	TenantScopeID uuid.UUID
	SiteID        uuid.UUID
	JA4           string
	SnapshotAt    time.Time
}

type AuthoritySnapshot struct {
	TenantScopeID           uuid.UUID
	SiteID                  uuid.UUID
	JA4                     string
	FilterFrom              time.Time
	FilterTo                time.Time
	FilterTimezone          string
	SnapshotAt              time.Time
	SnapshotExpiresAt       time.Time
	Consistency             string
	RequestCount            uint64
	ResponseBytes           uint64
	CurrentPolicy           *securitypolicy.Policy
	ExpectedBindingRevision int64
	ExpectedActiveVersion   int64
	TargetSnapshotID        uuid.UUID
	TargetSnapshotRevision  int64
	TargetSnapshotSHA256    [32]byte
	TargetNodeIDs           []uuid.UUID
	RolloutID               uuid.UUID
}

type Workflow struct {
	ID                      uuid.UUID
	TenantScopeID           uuid.UUID
	SiteID                  uuid.UUID
	ActorUserID             uuid.UUID
	ActorScopeID            uuid.UUID
	ActorScopeKind          string
	SessionID               uuid.UUID
	StepUpEvidenceID        uuid.UUID
	StepUpVerifiedAt        time.Time
	JA4                     string
	JA4SHA256               string
	FilterFrom              time.Time
	FilterTo                time.Time
	FilterTimezone          string
	SnapshotAt              time.Time
	SnapshotExpiresAt       time.Time
	RequestCount            uint64
	ResponseBytes           uint64
	Duration                time.Duration
	Reason                  string
	Phase                   Phase
	Revision                int64
	IdempotencyKey          string
	RequestID               string
	RequestSHA256           [32]byte
	CurrentPolicy           *securitypolicy.Policy
	ExpectedBindingRevision int64
	ExpectedActiveVersion   int64
	TargetSnapshotID        uuid.UUID
	TargetSnapshotRevision  int64
	TargetSnapshotSHA256    [32]byte
	TargetNodeIDs           []uuid.UUID
	RolloutID               uuid.UUID
	PolicyID                uuid.UUID
	PolicyRevision          int64
	BindingID               uuid.UUID
	BindingRevision         int64
	PublicationID           uuid.UUID
	EdgeState               string
	AttemptCount            int
	LastErrorCode           string
	AvailableAt             time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time
	Replayed                bool
}

type Claim struct {
	Workflow Workflow
	Token    uuid.UUID
	Action   string
}

type RunResult struct {
	Claimed  bool
	Workflow Workflow
}

type EdgeReceiptInput struct {
	ReceiptID            uuid.UUID
	TenantScopeID        uuid.UUID
	SiteID               uuid.UUID
	WorkflowID           uuid.UUID
	PolicyID             uuid.UUID
	PolicyRevision       int64
	BindingID            uuid.UUID
	BindingRevision      int64
	PublicationID        uuid.UUID
	RolloutID            uuid.UUID
	NodeID               uuid.UUID
	ConfigSHA256         [32]byte
	ReceiptSHA256        [32]byte
	ExpectedRevision     int64
	ActivePolicyRevision int64
	State                string
	ReasonCode           string
	ObservedAt           time.Time
}

type AuthoritySource interface {
	Resolve(context.Context, AuthorityRequest) (AuthoritySnapshot, error)
}

type PolicyWriter interface {
	Create(context.Context, securitypolicy.Actor, securitypolicy.CreateRequest) (securitypolicy.WriteResult, error)
	Update(context.Context, securitypolicy.Actor, securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error)
}

type PublicationWriter interface {
	Publish(context.Context, securitypolicy.Actor, securitybinding.PublishRequest) (securitybinding.Publication, error)
}

type WorkflowStore interface {
	Create(context.Context, Workflow) (Workflow, error)
	Claim(context.Context, string, time.Time, time.Duration) (Claim, bool, error)
	SetPolicy(context.Context, Claim, securitypolicy.WriteResult) (Workflow, error)
	SetPublication(context.Context, Claim, securitybinding.Publication) (Workflow, error)
	Retry(context.Context, Claim, string, time.Time) error
	Get(context.Context, uuid.UUID, uuid.UUID) (Workflow, error)
	SetEdgeReceipt(context.Context, EdgeReceiptInput) (Workflow, error)
}
