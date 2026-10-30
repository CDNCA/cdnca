package cccoord

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	SchemaVersion = "cdnca.security.cccoord/v1"

	ActionBlock   = "block"
	ActionRelease = "release"

	StateMonitoring     = "monitoring"
	StateBlockPending   = "block_pending"
	StateBlocked        = "blocked"
	StateReleasePending = "release_pending"
	StateReleased       = "released"
	StateFailed         = "failed"

	ReasonThresholdReached       = "cc_cross_node_threshold_reached"
	ReasonLocalFallback          = "cc_coordination_dependency_unavailable"
	ReasonFalsePositiveConfirmed = "false_positive_confirmed"
	ReasonCapacityRejected       = "cc_coordination_capacity_rejected"
	ReasonScopeRejected          = "cc_coordination_scope_rejected"

	RequestClassStandard   = "standard"
	RequestClassWebSocket  = "websocket"
	RequestClassSSE        = "sse"
	RequestClassTaskStream = "task_stream"
	RequestClassImport     = "import"
	RequestClassACME       = "acme"
	RequestClassHealth     = "health"
)

var (
	ErrInvalidInput        = errors.New("invalid CC coordination input")
	ErrScopeMismatch       = errors.New("CC coordination scope mismatch")
	ErrIdempotencyConflict = errors.New("CC coordination idempotency conflict")
	ErrGenerationConflict  = errors.New("CC coordination generation conflict")
	ErrCapacity            = errors.New("CC coordination capacity exhausted")
	ErrUnavailable         = errors.New("CC coordination dependency unavailable")
	identityPattern        = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

type Config struct {
	Window             time.Duration
	FactTTL            time.Duration
	BlockTTL           time.Duration
	ReleaseHold        time.Duration
	ClaimLease         time.Duration
	OperationTimeout   time.Duration
	HitThreshold       uint32
	NodeThreshold      uint32
	MaxFactsPerMessage int
	MaxActiveStates    int
	MaxClaims          int
	MaxAttempts        int
}

func DefaultConfig() Config {
	return Config{
		Window: time.Minute, FactTTL: 10 * time.Minute, BlockTTL: 10 * time.Minute,
		ReleaseHold: 30 * time.Minute, ClaimLease: 30 * time.Second, OperationTimeout: 5 * time.Second,
		HitThreshold: 20, NodeThreshold: 2, MaxFactsPerMessage: 1000,
		MaxActiveStates: 100_000, MaxClaims: 64, MaxAttempts: 8,
	}
}

func (config Config) validate() error {
	if config.Window < time.Second || config.Window > time.Hour ||
		config.FactTTL < config.Window || config.FactTTL > 24*time.Hour ||
		config.BlockTTL < time.Second || config.BlockTTL > 24*time.Hour ||
		config.ReleaseHold < config.BlockTTL || config.ReleaseHold > 7*24*time.Hour ||
		config.ClaimLease < time.Second || config.ClaimLease > time.Minute ||
		config.OperationTimeout <= 0 || config.OperationTimeout > time.Minute ||
		config.HitThreshold < 2 || config.HitThreshold > 1_000_000 ||
		config.NodeThreshold < 2 || config.NodeThreshold > 10_000 ||
		config.MaxFactsPerMessage < 1 || config.MaxFactsPerMessage > 1000 ||
		config.MaxActiveStates < 1 || config.MaxActiveStates > 1_000_000 ||
		config.MaxClaims < 1 || config.MaxClaims > 1000 || config.MaxAttempts < 1 || config.MaxAttempts > 16 {
		return ErrInvalidInput
	}
	return nil
}

type Fact struct {
	MessageID       string    `json:"message_id"`
	EventID         string    `json:"event_id"`
	TenantScopeID   uuid.UUID `json:"tenant_scope_id"`
	SiteID          uuid.UUID `json:"site_id"`
	NodeID          uuid.UUID `json:"node_id"`
	ConfigVersionID uuid.UUID `json:"config_version_id"`
	RuleID          uuid.UUID `json:"rule_id"`
	ClientCIDR      string    `json:"client_ip"`
	Host            string    `json:"host"`
	Path            string    `json:"path"`
	Method          string    `json:"method"`
	ListenerPort    uint16    `json:"listen_port"`
	Protocol        string    `json:"protocol"`
	RequestClass    string    `json:"request_class"`
	Action          string    `json:"action"`
	StatusCode      uint16    `json:"status_code"`
	OccurredAt      time.Time `json:"occurred_at"`
}

func normalizeFact(input Fact) (Fact, error) {
	if !identityPattern.MatchString(input.MessageID) || !identityPattern.MatchString(input.EventID) ||
		input.TenantScopeID == uuid.Nil || input.SiteID == uuid.Nil || input.NodeID == uuid.Nil ||
		input.ConfigVersionID == uuid.Nil || input.RuleID == uuid.Nil || input.OccurredAt.IsZero() ||
		!validHost(input.Host) || !validPath(input.Path) || !validMethod(input.Method) || input.ListenerPort == 0 ||
		(input.Protocol != "http" && input.Protocol != "https") || !validRequestClass(input.RequestClass) ||
		input.StatusCode < 400 || input.StatusCode > 599 || strings.TrimSpace(input.Action) == "" || len(input.Action) > 64 {
		return Fact{}, ErrInvalidInput
	}
	prefix, err := netip.ParsePrefix(input.ClientCIDR)
	if err != nil {
		address, addressErr := netip.ParseAddr(input.ClientCIDR)
		if addressErr != nil {
			return Fact{}, ErrInvalidInput
		}
		address = address.Unmap()
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	prefix = prefix.Masked()
	if prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().IsUnspecified() ||
		prefix.Addr().IsMulticast() || prefix.Addr().IsLinkLocalUnicast() {
		return Fact{}, ErrInvalidInput
	}
	input.ClientCIDR = prefix.String()
	input.OccurredAt = input.OccurredAt.UTC().Truncate(time.Microsecond)
	return input, nil
}

func automaticEligible(requestClass string) bool { return requestClass == RequestClassStandard }

func validRequestClass(value string) bool {
	switch value {
	case RequestClassStandard, RequestClassWebSocket, RequestClassSSE, RequestClassTaskStream,
		RequestClassImport, RequestClassACME, RequestClassHealth:
		return true
	default:
		return false
	}
}

func validHost(value string) bool {
	if value == "" || value != strings.ToLower(strings.TrimSpace(value)) || len(value) > 253 {
		return false
	}
	return !strings.ContainsAny(value, "/\r\n\x00")
}

func validPath(value string) bool {
	return strings.HasPrefix(value, "/") && len(value) <= 2048 &&
		!strings.ContainsAny(value, "?\r\n\x00")
}

func validMethod(value string) bool {
	if value == "" || len(value) > 16 {
		return false
	}
	for _, character := range value {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

type Settings struct {
	ID                  uuid.UUID   `json:"id"`
	TenantScopeID       uuid.UUID   `json:"tenant_scope_id"`
	SiteID              uuid.UUID   `json:"site_id"`
	SourceCCPolicyID    uuid.UUID   `json:"source_cc_policy_id"`
	SourcePolicyVersion int64       `json:"source_cc_policy_version"`
	ActorScopeID        uuid.UUID   `json:"actor_scope_id"`
	ActorUserID         uuid.UUID   `json:"actor_user_id"`
	TargetNodeIDs       []uuid.UUID `json:"target_node_ids"`
	Revision            int64       `json:"revision"`
	HitThreshold        uint32      `json:"hit_threshold"`
	NodeThreshold       uint32      `json:"node_threshold"`
	WindowSeconds       uint32      `json:"window_seconds"`
	BlockSeconds        uint32      `json:"block_seconds"`
	ReleaseHoldSecond   uint32      `json:"release_hold_seconds"`
	FactTTLSeconds      uint32      `json:"fact_ttl_seconds"`
	MaxFactsPerMessage  int         `json:"max_facts_per_message"`
	MaxActiveStates     int         `json:"max_active_states"`
	MaxClaims           int         `json:"max_claims"`
	MaxAttempts         int         `json:"max_attempts"`
	Enabled             bool        `json:"enabled"`
}

func normalizeSettings(input Settings) (Settings, error) {
	if input.ID == uuid.Nil || input.TenantScopeID == uuid.Nil || input.SiteID == uuid.Nil || input.SourceCCPolicyID == uuid.Nil ||
		input.SourcePolicyVersion < 1 || input.ActorScopeID != input.TenantScopeID || input.ActorUserID == uuid.Nil || input.Revision < 1 ||
		input.HitThreshold < 2 || input.HitThreshold > 1_000_000 || input.NodeThreshold < 2 ||
		input.WindowSeconds < 1 || input.WindowSeconds > 3600 || input.BlockSeconds < 1 || input.BlockSeconds > 86_400 ||
		input.ReleaseHoldSecond < input.BlockSeconds || input.ReleaseHoldSecond > 604_800 ||
		input.FactTTLSeconds < input.WindowSeconds || input.FactTTLSeconds > 86_400 ||
		input.MaxFactsPerMessage < 1 || input.MaxFactsPerMessage > 1000 ||
		input.MaxActiveStates < 1 || input.MaxActiveStates > 1_000_000 || input.MaxClaims < 1 || input.MaxClaims > 1000 ||
		input.MaxAttempts < 1 || input.MaxAttempts > 16 ||
		len(input.TargetNodeIDs) < int(input.NodeThreshold) || len(input.TargetNodeIDs) > 10_000 {
		return Settings{}, ErrInvalidInput
	}
	input.TargetNodeIDs = slices.Clone(input.TargetNodeIDs)
	slices.SortFunc(input.TargetNodeIDs, func(left, right uuid.UUID) int { return strings.Compare(left.String(), right.String()) })
	for index, nodeID := range input.TargetNodeIDs {
		if nodeID == uuid.Nil || index > 0 && nodeID == input.TargetNodeIDs[index-1] {
			return Settings{}, ErrInvalidInput
		}
	}
	return input, nil
}

type Envelope struct {
	SchemaVersion   uint16    `json:"schema_version"`
	Type            string    `json:"type"`
	MessageID       string    `json:"message_id"`
	ProducedAt      time.Time `json:"produced_at"`
	TenantScopeID   uuid.UUID `json:"tenant_id"`
	SiteID          uuid.UUID `json:"site_id"`
	NodeID          uuid.UUID `json:"node_id"`
	ConfigVersionID uuid.UUID `json:"config_version_id"`
	Events          []Fact    `json:"events"`
}

type State struct {
	ID                   uuid.UUID `json:"id"`
	TenantScopeID        uuid.UUID `json:"tenant_scope_id"`
	TenantID             uuid.UUID `json:"tenant_id"`
	SiteID               uuid.UUID `json:"site_id"`
	SourcePolicyID       uuid.UUID `json:"source_cc_policy_id"`
	RuleID               uuid.UUID `json:"rule_id"`
	ClientCIDR           string    `json:"client_cidr"`
	Host                 string    `json:"host"`
	Path                 string    `json:"path"`
	Method               string    `json:"method"`
	ListenerPort         uint16    `json:"listen_port"`
	Protocol             string    `json:"protocol"`
	RequestClass         string    `json:"request_class"`
	Generation           int64     `json:"generation"`
	State                string    `json:"state"`
	ReasonCode           string    `json:"reason_code"`
	HitCount             uint64    `json:"hit_count"`
	NodeCount            uint32    `json:"node_count"`
	CurrentPolicyVersion int64     `json:"current_policy_version"`
	LKGPolicyVersion     int64     `json:"lkg_policy_version"`
	ExpiresAt            time.Time `json:"expires_at"`
	ReleaseHoldTill      time.Time `json:"release_hold_until"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type ObserveResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
	Queued     int `json:"queued"`
}

type Action struct {
	ID              uuid.UUID
	TenantScopeID   uuid.UUID
	SiteID          uuid.UUID
	SourcePolicyID  uuid.UUID
	StateID         uuid.UUID
	RuleID          uuid.UUID
	ClientCIDR      string
	Host            string
	Path            string
	Method          string
	ListenerPort    uint16
	Protocol        string
	RequestClass    string
	Operation       string
	ReasonCode      string
	Generation      int64
	ExpectedVersion int64
	TargetNodeIDs   []uuid.UUID
	ExpiresAt       time.Time
	Attempts        int
	ClaimToken      uuid.UUID
	ActorScopeID    uuid.UUID
	ActorUserID     uuid.UUID
}

type PublicationResult struct {
	PublicationID uuid.UUID
	CandidateID   uuid.UUID
	PolicyVersion int64
}

type ActivationState uint8

const (
	ActivationPending ActivationState = iota
	ActivationActive
	ActivationFailed
)

type Activation struct {
	ActionID             uuid.UUID
	TenantScopeID        uuid.UUID
	SiteID               uuid.UUID
	StateID              uuid.UUID
	Generation           int64
	Operation            string
	PublicationID        uuid.UUID
	PolicyID             uuid.UUID
	PolicyVersion        int64
	CurrentPolicyVersion int64
	LKGPolicyVersion     int64
	ActorScopeID         uuid.UUID
	ActorUserID          uuid.UUID
}

type ReleaseInput struct {
	TenantScopeID      uuid.UUID
	SiteID             uuid.UUID
	RuleID             uuid.UUID
	ClientCIDR         string
	Host               string
	Path               string
	Method             string
	ListenerPort       uint16
	Protocol           string
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestID          string
}

type ReleaseResult struct {
	State    State `json:"state"`
	Replayed bool  `json:"replayed"`
}
