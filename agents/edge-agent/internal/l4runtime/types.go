package l4runtime

import (
	"errors"
	"time"
)

const SchemaVersionV1 = "cdnca.edge.l4/v1"

const (
	maxListeners          = 256
	maxPools              = 256
	maxEndpointsPerPool   = 64
	maxWeight             = 256
	maxFails              = 100
	minFailTimeoutMS      = 1_000
	maxFailTimeoutMS      = 300_000
	minConnectTimeoutMS   = 10
	maxConnectTimeoutMS   = 60_000
	minIdleTimeoutMS      = 100
	maxIdleTimeoutMS      = 86_400_000
	maxClientConnections  = 10_000
	maxTrafficHealthBytes = 1_024
	minTrafficHealthMS    = 10
	maxTrafficHealthMS    = 5_000
	maxTrafficAttempts    = 3
	maxTrustedProxyCIDRs  = 64
	minDrainTimeoutMS     = 100
	maxDrainTimeoutMS     = 60_000
	maxDrainMaxMS         = 7 * 86_400_000
	maximumStateFileBytes = 16 << 20
	// maxRetiredGenerations bounds the worker generations draining at once;
	// each keeps a full copy of the worker memory.
	maxRetiredGenerations = 4
)

// DefaultDrainMaxMS is how long a worker generation retired by a reload may
// keep serving its sessions when the configuration does not set drain_max_ms.
// drain_timeout_ms only bounds how long a reload waits for the retired
// workers to stop accepting; it never ends their sessions.
const DefaultDrainMaxMS = 86_400_000

var (
	ErrInvalidConfig = errors.New("invalid L4 configuration")
	ErrInvalidPath   = errors.New("invalid L4 runtime path")
	ErrConflict      = errors.New("L4 configuration version conflict")
	ErrCorruptState  = errors.New("corrupt L4 runtime state")
	ErrPrecheck      = errors.New("L4 configuration precheck failed")
	ErrActivation    = errors.New("L4 configuration activation failed")
	ErrUnsupported   = errors.New("unsupported L4 configuration")
)

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

type Endpoint struct {
	Address       string `json:"address"`
	Port          int    `json:"port"`
	Weight        int    `json:"weight"`
	MaxFails      int    `json:"max_fails"`
	FailTimeoutMS int    `json:"fail_timeout_ms"`
	Priority      int    `json:"priority,omitempty"`
	Backup        bool   `json:"backup,omitempty"`
}

type UpstreamPool struct {
	ID        string     `json:"id"`
	Endpoints []Endpoint `json:"endpoints"`
}

type TrafficHealthPolicy struct {
	Request          []byte `json:"request"`
	ExpectedResponse []byte `json:"expected_response"`
	TimeoutMS        int    `json:"timeout_ms"`
	Attempts         int    `json:"attempts"`
}

// PortEnd is a v2 port range (Port..PortEnd) seen through the legacy view
// (compatibleCompiledV2); v1 configurations never set it.
type Listener struct {
	ID                      string               `json:"id"`
	Disabled                bool                 `json:"disabled,omitempty"`
	Protocol                Protocol             `json:"protocol"`
	Address                 string               `json:"address"`
	Port                    int                  `json:"port"`
	PortEnd                 int                  `json:"port_end,omitempty"`
	UpstreamPoolID          string               `json:"upstream_pool_id"`
	ConnectTimeoutMS        int                  `json:"connect_timeout_ms"`
	IdleTimeoutMS           int                  `json:"idle_timeout_ms"`
	ProxyProtocolInbound    bool                 `json:"proxy_protocol_inbound"`
	ProxyProtocolOutbound   bool                 `json:"proxy_protocol_outbound"`
	ProxyProtocolV1         bool                 `json:"proxy_protocol_v1"`
	TrustedProxyCIDRs       []string             `json:"trusted_proxy_cidrs,omitempty"`
	MaxConnectionsPerClient int                  `json:"max_connections_per_client"`
	TrafficHealth           *TrafficHealthPolicy `json:"traffic_health,omitempty"`
}

type Config struct {
	SchemaVersion  string `json:"schema_version"`
	VersionID      string `json:"version_id"`
	DrainTimeoutMS int    `json:"drain_timeout_ms,omitempty"`
	// DrainMaxMS: see ListenerV2.DrainMaxMS. Omitted when nil, so existing
	// digests are unchanged.
	DrainMaxMS    *int           `json:"drain_max_ms,omitempty"`
	Listeners     []Listener     `json:"listeners"`
	UpstreamPools []UpstreamPool `json:"upstream_pools"`
}

type CompiledConfig struct {
	Config        Config
	Digest        string
	CanonicalJSON []byte
	NginxConfig   []byte
	v2            *ConfigV2
}

type ApplyState string

const (
	StateApplied ApplyState = "applied"
	StateFailed  ApplyState = "failed"
)

type ListenerOperation string

const (
	ListenerOperationCreate  ListenerOperation = "create"
	ListenerOperationEdit    ListenerOperation = "edit"
	ListenerOperationEnable  ListenerOperation = "enable"
	ListenerOperationDisable ListenerOperation = "disable"
	ListenerOperationDelete  ListenerOperation = "delete"
)

const (
	ListenerReasonCreated      = "LISTENER_CREATED"
	ListenerReasonEdited       = "LISTENER_EDITED"
	ListenerReasonEnabled      = "LISTENER_ENABLED"
	ListenerReasonDisabled     = "LISTENER_DISABLED"
	ListenerReasonDeleted      = "LISTENER_DELETED"
	ListenerReasonApplyAborted = "LISTENER_APPLY_ABORTED"
)

type ListenerResult struct {
	ID         string            `json:"id"`
	Operation  ListenerOperation `json:"operation"`
	ReasonCode string            `json:"reason_code"`
}

type Result struct {
	VersionID               string           `json:"version_id"`
	Digest                  string           `json:"digest"`
	State                   ApplyState       `json:"state"`
	ActiveVersionID         string           `json:"active_version_id,omitempty"`
	ActiveDigest            string           `json:"active_digest,omitempty"`
	RunningVersionUnchanged bool             `json:"running_version_unchanged"`
	ErrorCode               string           `json:"error_code,omitempty"`
	ListenerResults         []ListenerResult `json:"listener_results,omitempty"`
	AppliedAt               time.Time        `json:"applied_at,omitempty"`
}

type Status struct {
	Active    bool      `json:"active"`
	VersionID string    `json:"version_id,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
}
