package originroute

import (
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const SchemaV1 = "cdnca.edge.origin-route/v1"

const (
	MaxPools            = 64
	MaxEndpointsPerPool = 32
	MaxRoutes           = 256
	MaxListeners        = 16
	MaxAttempts         = 8
	MaxRevision         = uint64(1<<53 - 1)

	DefaultDNSQueryTimeoutMS  = uint32(1000)
	DefaultDNSMinTTLSeconds   = uint32(5)
	DefaultDNSMaxTTLSeconds   = uint32(300)
	DefaultDNSStaleTTLSeconds = uint32(900)
)

var (
	ErrInvalidPolicy = errors.New("invalid origin route policy")
	ErrConflict      = errors.New("origin route policy conflict")
	ErrPrecheck      = errors.New("origin route precheck failed")
	ErrReload        = errors.New("origin route reload failed")
	ErrHealth        = errors.New("origin route health check failed")
	ErrRollback      = errors.New("origin route rollback failed")
	ErrNoRoute       = errors.New("no origin route")
)

type NodeTier string

const (
	TierL1 NodeTier = "l1"
	TierL2 NodeTier = "l2"
)

type PoolKind string

const (
	PoolOrigin PoolKind = "origin"
	PoolL2     PoolKind = "l2"
)

type Algorithm = edgeconfig.OriginRouteAlgorithm

const (
	AlgorithmRoundRobin Algorithm = edgeconfig.OriginRouteAlgorithmRoundRobin
	AlgorithmIPHash     Algorithm = edgeconfig.OriginRouteAlgorithmIPHash
	AlgorithmURLHash    Algorithm = edgeconfig.OriginRouteAlgorithmURLHash
	AlgorithmLeastConn  Algorithm = edgeconfig.OriginRouteAlgorithmLeastConn
	AlgorithmRandom     Algorithm = edgeconfig.OriginRouteAlgorithmRandom
)

type Policy struct {
	Schema                string          `json:"schema"`
	Revision              uint64          `json:"revision"`
	TenantID              string          `json:"tenant_id"`
	SiteID                string          `json:"site_id"`
	VersionID             string          `json:"version_id"`
	Node                  Node            `json:"node"`
	Listeners             []Listener      `json:"listeners"`
	Pools                 []Pool          `json:"pools"`
	DefaultPoolID         string          `json:"default_pool_id"`
	DefaultFallbackPoolID string          `json:"default_fallback_pool_id,omitempty"`
	Routes                []Route         `json:"routes"`
	Retry                 RetryPolicy     `json:"retry"`
	L2                    L2Policy        `json:"l2"`
	Adaptive              *AdaptivePolicy `json:"adaptive,omitempty"`
	DNS                   *DNSPolicy      `json:"dns,omitempty"`
}

type DNSPolicy struct {
	Resolver        string `json:"resolver"`
	QueryTimeoutMS  uint32 `json:"query_timeout_ms"`
	MinTTLSeconds   uint32 `json:"min_ttl_seconds"`
	MaxTTLSeconds   uint32 `json:"max_ttl_seconds"`
	StaleTTLSeconds uint32 `json:"stale_ttl_seconds"`
}

type AdaptiveMode string

const (
	AdaptiveOff    AdaptiveMode = "off"
	AdaptiveShadow AdaptiveMode = "shadow"
	AdaptiveActive AdaptiveMode = "active"
)

type AdaptivePolicy struct {
	Version            uint8           `json:"version"`
	Mode               AdaptiveMode    `json:"mode"`
	MinimumSamples     uint16          `json:"minimum_samples"`
	SampleFreshnessMS  uint32          `json:"sample_freshness_ms"`
	PeakEWMAHalfLifeMS uint32          `json:"peak_ewma_half_life_ms"`
	ExplorationPercent uint8           `json:"exploration_percent"`
	SlowStart          SlowStartPolicy `json:"slow_start"`
	Outlier            OutlierPolicy   `json:"outlier"`
}

type SlowStartPolicy struct {
	InitialWeightPercent uint8  `json:"initial_weight_percent"`
	RampMS               uint32 `json:"ramp_ms"`
	HardTimeoutMS        uint32 `json:"hard_timeout_ms"`
}

type OutlierPolicy struct {
	MinimumSamples          uint16 `json:"minimum_samples"`
	ConsecutiveFailures     uint8  `json:"consecutive_failures"`
	FailureRatioPercent     uint8  `json:"failure_ratio_percent"`
	MaxEjectionPercent      uint8  `json:"max_ejection_percent"`
	BaseEjectionMS          uint32 `json:"base_ejection_ms"`
	MaxEjectionMS           uint32 `json:"max_ejection_ms"`
	RecoveryProbeIntervalMS uint32 `json:"recovery_probe_interval_ms"`
}

type Node struct {
	ID     string   `json:"id"`
	Region string   `json:"region"`
	Tier   NodeTier `json:"tier"`
}

type Listener struct {
	ID                string `json:"id"`
	Address           string `json:"address"`
	Port              uint16 `json:"port"`
	IngressSourceIPv4 string `json:"ingress_source_ipv4,omitempty"`
	IngressSourceIPv6 string `json:"ingress_source_ipv6,omitempty"`
}

type Pool struct {
	ID        string     `json:"id"`
	Kind      PoolKind   `json:"kind"`
	Algorithm Algorithm  `json:"algorithm,omitempty"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	NodeID string `json:"node_id,omitempty"`
	Weight uint8  `json:"weight"`
}

type Route struct {
	ID             string   `json:"id"`
	Priority       int      `json:"priority"`
	PathPrefix     string   `json:"path_prefix,omitempty"`
	NodeRegions    []string `json:"node_regions,omitempty"`
	ClientCIDRs    []string `json:"client_cidrs,omitempty"`
	// Hosts match the request host: exact names, or "*.x" for any deeper
	// subdomain of x (a site's leading wildcard domain).
	Hosts          []string `json:"hosts,omitempty"`
	PoolID         string   `json:"pool_id"`
	FallbackPoolID string   `json:"fallback_pool_id,omitempty"`
}

type RetryPolicy struct {
	Methods          []string `json:"methods"`
	MaxAttempts      uint8    `json:"max_attempts"`
	ConnectTimeoutMS uint32   `json:"connect_timeout_ms"`
	ReadTimeoutMS    uint32   `json:"read_timeout_ms"`
	TotalBudgetMS    uint32   `json:"total_budget_ms"`
}

type L2Policy struct {
	FailureThreshold  uint8  `json:"failure_threshold"`
	RecoveryThreshold uint8  `json:"recovery_threshold"`
	ProbeIntervalMS   uint32 `json:"probe_interval_ms"`
	MaxHops           uint8  `json:"max_hops"`
}

type RequestFacts struct {
	Path       string
	NodeRegion string
	ClientIP   string
	ListenerID string
	HopCount   uint8
}

type Decision struct {
	RouteID        string
	PoolID         string
	FallbackPoolID string
	Defaulted      bool
	Explanation    string
}

type AttemptState struct {
	Method          string
	Attempt         uint8
	Elapsed         time.Duration
	HasRequestBody  bool
	StreamingBody   bool
	ResponseStarted bool
	Failure         string
}

type RetryDecision struct {
	Retry      bool
	Remaining  time.Duration
	ResultCode string
	Reason     string
}

const (
	ResultCodeRetry                = "retry"
	ResultCodeStop                 = "stop"
	ResultCodeL2Attempt            = "l2_attempt"
	ResultCodeDirectOriginFallback = "direct_origin_fallback"
)

const (
	ReasonTotalBudgetExhausted     = "total_budget_exhausted"
	ReasonResponseAlreadyStarted   = "response_already_started"
	ReasonRequestBodyNotReplayable = "request_body_not_replayable"
	ReasonMethodNotRetryable       = "method_not_retryable"
	ReasonAttemptLimitReached      = "attempt_limit_reached"
	ReasonRetryableUpstreamFailure = "retryable_upstream_failure"
	ReasonFailureNotRetryable      = "failure_not_retryable"
	ReasonL2NotSelected            = "l2_not_selected"
	ReasonDirectOriginRequired     = "direct_origin_required"
	ReasonDirectOriginAttemptLimit = "direct_origin_attempt_limit_reached"
	ReasonL2RetryableFailure       = "l2_retryable_failure"
	ReasonCircuitClosed            = "circuit_closed"
	ReasonCircuitOpen              = "circuit_open"
	ReasonHalfOpenProbe            = "half_open_probe"
	ReasonHalfOpenProbeInFlight    = "half_open_probe_in_flight"
	ReasonCircuitStateInvalid      = "circuit_state_invalid"
)

type L2FallbackState struct {
	Attempt               AttemptState
	DirectOriginAttempted bool
}

type L2FallbackDecision struct {
	Fallback   bool
	PoolID     string
	Remaining  time.Duration
	ResultCode string
	ReasonCode string
}

type CircuitPhase string

const (
	CircuitClosed   CircuitPhase = "closed"
	CircuitOpen     CircuitPhase = "open"
	CircuitHalfOpen CircuitPhase = "half_open"
)

type CircuitState struct {
	Phase                CircuitPhase
	ConsecutiveFailures  uint8
	ConsecutiveSuccesses uint8
	ProbeAfter           time.Time
	ProbeInFlight        bool
}

type L2AttemptDecision struct {
	State      CircuitState
	Allowed    bool
	Probe      bool
	ResultCode string
	ReasonCode string
}

type Artifact struct {
	VersionID string
	Revision  uint64
	Digest    string
	StateKey  string
	Policy    []byte
	Nginx     []byte
}

type ApplyResult struct {
	VersionID      string
	Digest         string
	PreviousDigest string
	Changed        bool
}
