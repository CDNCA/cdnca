package packagesubscription

import (
	"encoding/json"
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/bridgeauth"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
)

const (
	ScopePlatform = "platform"
	ScopeTenant   = "tenant"

	LifecycleActive    = "active"
	LifecycleCancelled = "cancelled"

	ResourceSites   = "sites"
	ResourceDomains = "domains"
	ResourceNodes   = "nodes"

	TaskActionActivate = "activate"
	TaskActionSuspend  = "suspend"
	TaskActionRecover  = "recover"

	TaskReasonOpened          = "opened"
	TaskReasonRenewed         = "renewed"
	TaskReasonCancelled       = "cancelled"
	TaskReasonExpired         = "expired"
	TaskReasonTrafficExceeded = "traffic_exceeded"
	TaskReasonNewCycle        = "new_cycle"

	maxCountLimit = int64(1_000_000_000)
)

var (
	ErrInvalidInput        = errors.New("invalid package subscription input")
	ErrUnauthenticated     = errors.New("package subscription authentication required")
	ErrPermissionDenied    = errors.New("package subscription permission denied")
	ErrNotFound            = errors.New("package subscription not found")
	ErrProductNotFound     = errors.New("package product version not available")
	ErrRevisionConflict    = errors.New("package subscription revision conflict")
	ErrIdempotencyConflict = errors.New("package subscription idempotency conflict")
	ErrInvalidState        = errors.New("invalid package subscription state")
	ErrUsageOverflow       = errors.New("package subscription usage overflows uint64")
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
	ScopeKind string
	// bridge is the billing bridge credential (ADR 0019 §4.4); only
	// NewBridgeActor sets it.
	bridge *bridgeauth.Grant
}

// NewBridgeActor is the billing bridge facade's actor: the owner scope acting
// through a verified bridge key as the key's creator, without a session.
func NewBridgeActor(grant *bridgeauth.Grant) (Actor, error) {
	if !grant.Valid() {
		return Actor{}, ErrUnauthenticated
	}
	actor := Actor{UserID: grant.ActingUserID(), ScopeID: grant.OwnerScopeID(), ScopeKind: ScopeTenant, bridge: grant}
	if grant.Platform() {
		actor.ScopeKind = ScopePlatform
	}
	return actor, nil
}

// Bridge reports whether the actor came from the billing bridge facade.
func (actor Actor) Bridge() bool { return actor.bridge != nil }

type ProductSnapshot struct {
	ID       uuid.UUID       `json:"id"`
	Revision int64           `json:"revision"`
	Name     string          `json:"name"`
	Spec     json.RawMessage `json:"spec"`
}

type QuotaSnapshot struct {
	Sites        int64 `json:"sites"`
	Domains      int64 `json:"domains"`
	Nodes        int64 `json:"nodes"`
	TrafficBytes int64 `json:"traffic_bytes"`
}

type RationalSnapshot struct {
	Numerator   uint64 `json:"numerator"`
	Denominator uint64 `json:"denominator"`
}

type PeriodSnapshot struct {
	StartsAt      time.Time                 `json:"starts_at"`
	EndsAt        time.Time                 `json:"ends_at"`
	TimeZone      string                    `json:"timezone"`
	CyclePolicy   packageperiod.CyclePolicy `json:"cycle_policy"`
	TrafficFactor RationalSnapshot          `json:"traffic_factor"`
}

type Subscription struct {
	ID              uuid.UUID       `json:"id"`
	TenantScopeID   uuid.UUID       `json:"tenant_scope_id"`
	Product         ProductSnapshot `json:"product"`
	Quotas          QuotaSnapshot   `json:"quotas"`
	Period          PeriodSnapshot  `json:"period"`
	LifecycleStatus string          `json:"lifecycle_status"`
	CancelledAt     *time.Time      `json:"cancelled_at"`
	// SuspendedAt / SuspendReason: a suspended subscription keeps its term and
	// configuration but its sites and forwards are not published (migration 555).
	SuspendedAt   *time.Time `json:"suspended_at,omitempty"`
	SuspendReason string     `json:"suspend_reason,omitempty"`
	Revision      int64      `json:"revision"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type TaskIntent struct {
	SubscriptionID uuid.UUID `json:"subscription_id"`
	TenantScopeID  uuid.UUID `json:"tenant_scope_id"`
	Action         string    `json:"action"`
	Reason         string    `json:"reason"`
	ResetKey       string    `json:"reset_key,omitempty"`
	DesiredEnabled bool      `json:"desired_enabled"`
}

type MutationResult struct {
	Subscription Subscription `json:"subscription"`
	Intent       *TaskIntent  `json:"intent,omitempty"`
	Replayed     bool         `json:"-"`
}

type OpenRequest struct {
	TenantScopeID   uuid.UUID
	OwnerUserID     uuid.UUID
	ProductID       uuid.UUID
	ProductRevision int64
	SiteLimit       int64
	NodeLimit       int64
	Terms           packageperiod.Terms
	TimeZone        string
	CyclePolicy     packageperiod.CyclePolicy
	TrafficFactor   packageperiod.TrafficFactor
	IdempotencyKey  string
	RequestID       string
}

type RenewRequest struct {
	TenantScopeID    uuid.UUID
	SubscriptionID   uuid.UUID
	ExpectedRevision int64
	Terms            packageperiod.Terms
	IdempotencyKey   string
	RequestID        string
}

// SuspendRequest suspends (Suspend true) or unsuspends one subscription. A
// subscription already in the requested state is left as it is (success).
type SuspendRequest struct {
	TenantScopeID  uuid.UUID
	SubscriptionID uuid.UUID
	Suspend        bool
	Reason         string
	IdempotencyKey string
	RequestID      string
}

type CancelRequest struct {
	TenantScopeID    uuid.UUID
	SubscriptionID   uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type Usage struct {
	Sites             int64
	Domains           int64
	Nodes             int64
	OtherTrafficBytes uint64
	TCPTrafficBytes   uint64
}

type QuotaWarning struct {
	Resource string `json:"resource"`
	Limit    uint64 `json:"limit"`
	Used     uint64 `json:"used"`
}

type Evaluation struct {
	ResetKey         string         `json:"reset_key,omitempty"`
	BilledTraffic    uint64         `json:"billed_traffic"`
	BlockedResources []string       `json:"blocked_resources"`
	Warnings         []QuotaWarning `json:"warnings"`
	Intent           *TaskIntent    `json:"intent,omitempty"`
}
