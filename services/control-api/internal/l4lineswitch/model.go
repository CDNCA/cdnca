package l4lineswitch

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid L4 line switch input")
	ErrUnauthenticated     = errors.New("L4 line switch authentication required")
	ErrPermissionDenied    = errors.New("L4 line switch permission denied")
	ErrNotFound            = errors.New("L4 line switch not found")
	ErrConflict            = errors.New("L4 line switch conflict")
	ErrIdempotencyConflict = errors.New("L4 line switch idempotency conflict")
	ErrUnsafeRollback      = errors.New("L4 line switch rollback could not be restored safely")
	ErrPersistence         = errors.New("L4 line switch persistence failed")
)

const (
	ReconcilerWorkloadID = "control-api.l4-line-switch-reconciler"
	StatePreparing       = "preparing"
	StateHealthGate      = "health_gate"
	StateDrainingOld     = "draining_old"
	StateCompensatingOld = "compensating_old"
	StateCompleted       = "completed"
	StateRolledBack      = "rolled_back"
	StateNeedsAttention  = "needs_attention"
	RolloutPending       = "pending"
	RolloutSucceeded     = "succeeded"
	RolloutFailed        = "failed"
	DrainPending         = "pending"
	DrainCompleted       = "completed"
	DrainFailed          = "failed"
	PermissionRead       = "edge_publications.read"
	PermissionManage     = "edge_publications.manage"
	maxSwitchNodes       = 10000
)

type Actor struct {
	UserID, ScopeID, SessionID uuid.UUID
	ScopeKind                  string
	Credential                 string
	WorkloadID                 string
}

func ReconcilerActor() Actor { return Actor{WorkloadID: ReconcilerWorkloadID} }

type SnapshotReference struct {
	ID       uuid.UUID `json:"id"`
	Revision int64     `json:"revision"`
	SHA256   [32]byte  `json:"sha256"`
}

type Snapshot struct {
	Reference SnapshotReference `json:"reference"`
	NodeIDs   []uuid.UUID       `json:"node_ids"`
}

type HealthPolicy struct {
	ActivationTimeout            time.Duration `json:"activation_timeout"`
	ObservationWindow            time.Duration `json:"observation_window"`
	RequiredConsecutiveSuccesses uint32        `json:"required_consecutive_successes"`
}

type DrainPolicy struct {
	HealthTimeout time.Duration `json:"health_timeout"`
	MaxDrain      time.Duration `json:"max_drain"`
}

type StartRequest struct {
	Actor                  Actor
	ConfigurationScopeID   uuid.UUID
	ExpectedSourceRevision int64
	From, To               SnapshotReference
	Health                 HealthPolicy
	Drain                  DrainPolicy
	MaxAttempts            uint32
	Deadline               time.Time
	IdempotencyKey         string
	RequestID              uuid.UUID
	CorrelationID          uuid.UUID
	Traceparent            string
}

type Publication struct {
	ID, RolloutID, ConfigVersionID uuid.UUID
}

type Switch struct {
	ID                      uuid.UUID               `json:"id"`
	ConfigurationScopeID    uuid.UUID               `json:"configuration_scope_id"`
	ExpectedSourceRevision  int64                   `json:"expected_source_revision"`
	From, To                Snapshot                `json:"-"`
	PrepareNodes            []uuid.UUID             `json:"-"`
	RetiringNodes           []uuid.UUID             `json:"retiring_nodes"`
	Health                  HealthPolicy            `json:"-"`
	Drain                   DrainPolicy             `json:"-"`
	MaxAttempts             uint32                  `json:"-"`
	Deadline                time.Time               `json:"deadline"`
	RequestID               uuid.UUID               `json:"request_id"`
	CorrelationID           uuid.UUID               `json:"correlation_id"`
	Traceparent             string                  `json:"-"`
	State                   string                  `json:"state"`
	StateRevision           int64                   `json:"state_revision"`
	PreparePublication      Publication             `json:"prepare_publication"`
	CompensationPublication Publication             `json:"compensation_publication"`
	DrainCommands           map[uuid.UUID]uuid.UUID `json:"drain_commands"`
	ErrorCode               string                  `json:"error_code,omitempty"`
	// DNSGate is the last DNS check while the switch waits in health_gate. It
	// is read-side only: encodeSwitch never persists it.
	DNSGate   *DNSGateStatus `json:"dns_gate,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Replayed  bool           `json:"replayed,omitempty"`
}

type Claim struct {
	Switch         Switch
	IdempotencyKey string
	RequestDigest  [32]byte
}

type Store interface {
	Claim(context.Context, Actor, Claim) (Switch, bool, error)
	Get(context.Context, Actor, uuid.UUID, uuid.UUID, string) (Switch, error)
	Latest(context.Context, Actor, uuid.UUID, string) (Switch, error)
	CompareAndSwap(context.Context, Actor, Switch, Switch) error
}

type ActiveSwitch struct {
	ConfigurationScopeID uuid.UUID
	SwitchID             uuid.UUID
}

type ActiveSwitchReader interface {
	ListActive(context.Context, int) ([]ActiveSwitch, error)
}

type SnapshotResolver interface {
	Resolve(context.Context, Actor, uuid.UUID, SnapshotReference) (Snapshot, error)
}

type PublicationCoordinator interface {
	Prepare(context.Context, Actor, Switch) (Publication, error)
	Compensate(context.Context, Actor, Switch) (Publication, error)
	RolloutStatus(context.Context, Actor, Switch, uuid.UUID) (string, error)
}

type TargetCoordinator interface {
	Activate(context.Context, Actor, Switch) error
	Restore(context.Context, Actor, Switch) error
}

const (
	// DNSGateReady: every CNAME owner of the scope stopped resolving to the
	// retiring nodes at least 2×TTL ago.
	DNSGateReady = "ready"
	// DNSGateRetargetPending: an owner still resolves to a retiring node, or
	// its retarget/allocation has not committed yet.
	DNSGateRetargetPending = "retarget_pending"
	// DNSGatePropagationWait: committed, but resolver caches may still hold
	// the old answer (inside 2×TTL, at least 5 minutes).
	DNSGatePropagationWait = "propagation_wait"
)

// DNSGateStatus is what stands between a healthy new line and draining the
// old nodes' listeners (FX27).
type DNSGateStatus struct {
	State         string     `json:"state"`
	Owners        int        `json:"owners"`
	PendingOwners int        `json:"pending_owners"`
	ReadyAt       *time.Time `json:"ready_at,omitempty"`
}

type DNSGate interface {
	Check(context.Context, Actor, Switch) (DNSGateStatus, error)
}

type DrainCoordinator interface {
	Build(context.Context, Actor, Switch) (map[uuid.UUID]*agentv1.DrainCommand, error)
	Publish(context.Context, Actor, *agentv1.DrainCommand) error
	Status(context.Context, Actor, *agentv1.DrainCommand) (string, error)
}
