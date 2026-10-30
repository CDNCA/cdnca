package nodescheduler

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	HealthUnknown   = "unknown"
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"

	maxEndpoints       = 512
	maxPriority        = 65535
	maxWeight          = 100
	maxProbeAge        = 24 * time.Hour
	maxProbeFutureSkew = 5 * time.Minute
)

var (
	ErrInvalidInput              = errors.New("invalid node scheduling input")
	ErrPermissionDenied          = errors.New("node scheduling permission denied")
	ErrNotFound                  = errors.New("node line group not found")
	ErrNameConflict              = errors.New("node line group name conflict")
	ErrRevisionConflict          = errors.New("node line group revision conflict")
	ErrIdempotencyConflict       = errors.New("node scheduling idempotency conflict")
	ErrNoHealthyEndpoint         = errors.New("node line group has no healthy endpoint")
	ErrStaleProbe                = errors.New("node health probe is stale")
	ErrProbeConflict             = errors.New("node health probe sequence conflict")
	ErrTargetSnapshotConflict    = errors.New("node target snapshot conflict")
	ErrTargetSnapshotUnavailable = errors.New("node target snapshot unavailable")
	ErrTopologyCycle             = errors.New("node scheduling topology cycle")
	ErrPlatformWriteDenied       = errors.New("platform node scheduling write denied")
	ErrCredentialInvalid         = errors.New("node scheduling credential invalid")
	ErrReferenceConflict         = errors.New("node line group reference conflict")
	// ErrEndpointAddressNotOnNode: an endpoint bound to a node must use one of
	// that node's addresses (primary IPv4/IPv6 or a secondary IP).
	ErrEndpointAddressNotOnNode = errors.New("node line endpoint address is not an address of its node")
)

const (
	CredentialSession = "session"
	CredentialAPIKey  = "api_key"

	StrategyWeightedBaseline   = "weighted_baseline"
	StrategyWeightedRendezvous = "weighted_rendezvous"
	StrategyP2CLeastLoaded     = "p2c_least_loaded"

	FailoverPrimaryOffline            = "primary_offline"
	FailoverOnlineLessThanBackupCount = "online_less_than_backup_count"

	ReasonBaselineWeightedSelected     = "baseline_weighted_selected"
	ReasonWeightedRendezvousSelected   = "weighted_rendezvous_selected"
	ReasonP2CLeastLoadedSelected       = "p2c_least_loaded_selected"
	ReasonTelemetryInsufficient        = "telemetry_insufficient"
	ReasonTelemetryStaleFallback       = "telemetry_stale_fallback"
	ReasonTelemetryUnavailableFallback = "telemetry_unavailable_fallback"
	ReasonSingleCandidateFallback      = "single_candidate_fallback"
	ReasonNoHealthyEndpoint            = "no_healthy_endpoint"
	ReasonTopologyCycleRejected        = "topology_cycle_rejected"
	ReasonPrimaryPrioritySelected      = "primary_priority_selected"
	ReasonBackupPrioritySelected       = "backup_priority_selected"

	EndpointDispositionCandidate        = "candidate"
	EndpointDispositionStandby          = "standby"
	EndpointDispositionDisabled         = "disabled"
	EndpointDispositionSelectorMismatch = "selector_mismatch"
	EndpointDispositionLessSpecific     = "less_specific"
	EndpointDispositionUnknown          = "health_unknown"
	EndpointDispositionUnhealthy        = "health_unhealthy"
	EndpointDispositionStale            = "health_stale"
)

type Credential struct {
	Kind string
	Raw  string
}

type Actor struct {
	UserID        uuid.UUID
	ScopeID       uuid.UUID
	ScopeKind     string
	TargetScopeID uuid.UUID
	Credential    Credential
}

func (actor Actor) ResourceScopeID() uuid.UUID {
	if actor.TargetScopeID != uuid.Nil {
		return actor.TargetScopeID
	}
	return actor.ScopeID
}

type HealthPolicy struct {
	ProbeInterval     time.Duration `json:"probe_interval"`
	ProbeTimeout      time.Duration `json:"probe_timeout"`
	FailureThreshold  int           `json:"failure_threshold"`
	RecoveryThreshold int           `json:"recovery_threshold"`
	FailureDebounce   time.Duration `json:"failure_debounce"`
	RecoveryDebounce  time.Duration `json:"recovery_debounce"`
}

func DefaultHealthPolicy() HealthPolicy {
	return HealthPolicy{
		ProbeInterval: 10 * time.Second, ProbeTimeout: 3 * time.Second,
		FailureThreshold: 3, RecoveryThreshold: 3,
	}
}

type Endpoint struct {
	ID        uuid.UUID   `json:"id"`
	DisplayID string      `json:"display_id,omitempty"`
	NodeID    uuid.UUID   `json:"node_id,omitempty"`
	Address   string      `json:"address"`
	Port      int         `json:"port"`
	Region    string      `json:"region"`
	Carrier   string      `json:"carrier"`
	Priority  int         `json:"priority"`
	SortOrder int         `json:"sort_order"`
	Weight    int         `json:"weight"`
	Enabled   bool        `json:"enabled"`
	Health    HealthState `json:"health"`
	// Published is node_line_endpoint_published.published, only loaded for
	// line group reads (List/GetCurrent); nil when not loaded.
	Published *bool `json:"published,omitempty"`
}

type HealthState struct {
	Status               string     `json:"status"`
	ConsecutiveSuccesses int        `json:"consecutive_successes"`
	ConsecutiveFailures  int        `json:"consecutive_failures"`
	StreakStartedAt      *time.Time `json:"streak_started_at,omitempty"`
	LastSequence         int64      `json:"last_sequence"`
	LastObservedAt       *time.Time `json:"last_observed_at,omitempty"`
	LastReceivedAt       *time.Time `json:"last_received_at,omitempty"`
	LastProbeDigest      []byte     `json:"-"`
	LastProbeHealthy     *bool      `json:"-"`
	LastChangedAt        time.Time  `json:"last_changed_at"`
	RowRevision          int64      `json:"row_revision"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type LineGroupRevision struct {
	GroupID             uuid.UUID    `json:"group_id"`
	DisplayID           string       `json:"display_id"`
	TenantScopeID       uuid.UUID    `json:"tenant_scope_id"`
	Revision            int64        `json:"revision"`
	Name                string       `json:"name"`
	Region              string       `json:"region"`
	ResolvedValue       string       `json:"resolved_value"`
	IPv4ResolvedValue   string       `json:"ipv4_resolved_value"`
	L2ConfigID          *uuid.UUID   `json:"l2_config_id"`
	FailoverMode        string       `json:"failover_mode"`
	Note                string       `json:"note"`
	SortOrder           int          `json:"sort_order"`
	Policy              HealthPolicy `json:"health_policy"`
	Endpoints           []Endpoint   `json:"endpoints"`
	ConfigurationDigest []byte       `json:"configuration_digest"`
	CreatedByUserID     uuid.UUID    `json:"created_by_user_id"`
	CreatedAt           time.Time    `json:"created_at"`
	SealedAt            time.Time    `json:"sealed_at"`
	// IsPlatformDefault is current line group state, not revision state:
	// sites without a package freeze CNAME targets from it (migration 533).
	IsPlatformDefault bool `json:"is_platform_default"`
	// BackupStates is current backup IP state per address family (migration
	// 571), only loaded for line group reads (List/GetCurrent).
	BackupStates []LineBackupState `json:"backup_states,omitempty"`
}

type LineGroupStatistics struct {
	NodeCount    int64 `json:"node_count"`
	SiteCount    int64 `json:"site_count"`
	ForwardCount int64 `json:"forward_count"`
}

// Line group purposes (migration 422, ADR 0012 §3.3). A market_supply group
// is the hidden platform group a seller's node selection becomes: only
// PutMarketSupplyGroup/DeleteMarketSupplyGroup write it, and the line group
// API (List, Get*, Decide, Rollback, Delete) does not see it.
const (
	PurposeGeneral      = "general"
	PurposeMarketSupply = "market_supply"
)

type PutGroupRequest struct {
	GroupID           uuid.UUID
	ExpectedRevision  int64
	Name              string
	Region            string
	ResolvedValue     string
	IPv4ResolvedValue string
	L2ConfigID        *uuid.UUID
	FailoverMode      string
	Note              string
	SortOrder         int
	Policy            HealthPolicy
	Endpoints         []Endpoint
	IdempotencyKey    string
	RequestID         string
	// Purpose is set by PutMarketSupplyGroup; the line group API leaves it
	// empty (general).
	Purpose string
}

type WriteResult struct {
	Group    LineGroupRevision `json:"group"`
	Replayed bool              `json:"-"`
}

type DeleteResult struct {
	GroupID   uuid.UUID `json:"group_id"`
	ScopeID   uuid.UUID `json:"scope_id"`
	Revision  int64     `json:"revision"`
	DeletedAt time.Time `json:"deleted_at"`
	Replayed  bool      `json:"-"`
}

type ProbeResult struct {
	TenantScopeID uuid.UUID   `json:"tenant_scope_id"`
	GroupID       uuid.UUID   `json:"group_id"`
	Revision      int64       `json:"revision"`
	EndpointID    uuid.UUID   `json:"endpoint_id"`
	Health        HealthState `json:"health"`
	Transitioned  bool        `json:"transitioned"`
	Replayed      bool        `json:"replayed"`
}

type ProbeRequest struct {
	TenantScopeID uuid.UUID
	GroupID       uuid.UUID
	Revision      int64
	EndpointID    uuid.UUID
	Sequence      int64
	ObservedAt    time.Time
	Healthy       bool
}

type Selector struct {
	Region  string
	Carrier string
}

type Plan struct {
	TenantScopeID       uuid.UUID            `json:"tenant_scope_id"`
	GroupID             uuid.UUID            `json:"group_id"`
	Revision            int64                `json:"revision"`
	ConfigurationDigest []byte               `json:"configuration_digest"`
	Selector            Selector             `json:"selector"`
	EvaluatedAt         time.Time            `json:"evaluated_at"`
	Priority            int                  `json:"priority"`
	TierReason          string               `json:"tier_reason"`
	Candidates          []Endpoint           `json:"candidates"`
	Standby             []Endpoint           `json:"standby"`
	Evaluations         []EndpointEvaluation `json:"evaluations"`
	Digest              [32]byte             `json:"digest"`
}

type EndpointEvaluation struct {
	Endpoint    Endpoint `json:"endpoint"`
	Disposition string   `json:"disposition"`
}

type DecisionRequest struct {
	Selector  Selector `json:"selector"`
	Strategy  string   `json:"strategy"`
	StableKey string   `json:"stable_key"`
	RequestID string   `json:"-"`
}

type Decision struct {
	Endpoint Endpoint `json:"endpoint"`
	Plan     Plan     `json:"plan"`
	Strategy string   `json:"strategy"`
	Reason   string   `json:"reason"`
	Fallback bool     `json:"fallback"`
}

type LoadSample struct {
	Inflight   int64
	ObservedAt time.Time
}

type LoadProvider interface {
	Loads(context.Context, uuid.UUID, []Endpoint) (map[uuid.UUID]LoadSample, error)
}

type TargetSnapshotReference struct {
	ID       uuid.UUID
	Revision int64
	SHA256   [32]byte
}

type TargetSnapshot struct {
	Reference                 TargetSnapshotReference
	TenantScopeID             uuid.UUID
	SourceLineGroupID         uuid.UUID
	SourceRevision            int64
	SourceConfigurationDigest []byte
	NodeIDs                   []uuid.UUID
	IdentityFacts             []SnapshotIdentity
	Replayed                  bool
}

type SnapshotIdentity struct {
	NodeID             uuid.UUID
	Tier               string
	TopologyRevision   int64
	SourceLineGroupID  uuid.UUID
	SourceRevision     int64
	EndpointID         *uuid.UUID
	MTLSIdentitySHA256 []byte
}
