package l4runtime

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const SchemaVersionV2 = "cdnca.edge.l4/v2"

const maxExactJSONInteger = int64(1<<53 - 1)

var (
	ErrDNSUnavailable = errors.New("L4 DNS address set is unavailable")
	ErrDNSStale       = errors.New("L4 DNS last-known-good address set is stale")
)

type GeoAction string

const (
	GeoActionAllow GeoAction = "allow"
	GeoActionBlock GeoAction = "block"
)

// PortEnd (tcp/udp v9) makes a socket the port range Port..PortEnd
// (edgeconfig.ValidL4PortRange); 0 is the single Port.
type ListenerSocketV2 struct {
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	PortEnd  int      `json:"port_end,omitempty"`
}

type AdditionalListenerV2 struct {
	ID       string   `json:"id"`
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	PortEnd  int      `json:"port_end,omitempty"`
}

// FollowPort (tcp/udp v9) connects to the origin on the port the client
// connected to (Port then equals the primary listener's Port).
//
// Origins and Balance (tcp/udp v11) are edgeconfig.L4EndpointV2's: several
// weighted IP origins on Port (Address is the first), "ip_hash" or round robin.
type EndpointV2 struct {
	Address    string     `json:"address,omitempty"`
	Host       string     `json:"host,omitempty"`
	Port       int        `json:"port"`
	FollowPort bool       `json:"follow_port,omitempty"`
	Origins    []OriginV2 `json:"origins,omitempty"`
	Balance    string     `json:"balance,omitempty"`
}

// OriginV2 is edgeconfig.L4OriginV2 (one contract).
type OriginV2 = edgeconfig.L4OriginV2

type DNSPolicyV2 struct {
	PositiveMinTTLSeconds int64 `json:"positive_min_ttl_seconds"`
	PositiveMaxTTLSeconds int64 `json:"positive_max_ttl_seconds"`
	NegativeTTLSeconds    int64 `json:"negative_ttl_seconds"`
	StaleIfErrorSeconds   int64 `json:"stale_if_error_seconds"`
	AllowPrivateAddresses bool  `json:"allow_private_addresses"`
}

type RegionCIDRsV2 struct {
	Region string   `json:"region"`
	CIDRs  []string `json:"cidrs"`
}

type GeoPolicyV2 struct {
	Enabled             bool            `json:"enabled"`
	TenantID            string          `json:"tenant_id"`
	SiteID              string          `json:"site_id"`
	StreamID            string          `json:"stream_id"`
	Revision            int64           `json:"revision"`
	UnknownRegionAction GeoAction       `json:"unknown_region_action"`
	TrustedProxyCIDRs   []string        `json:"trusted_proxy_cidrs"`
	BlockedRegions      []string        `json:"blocked_regions"`
	RegionCIDRs         []RegionCIDRsV2 `json:"region_cidrs"`
}

// StreamRuntimeSpecV2 is the control-side, single-stream wire contract. It is
// deliberately distinct from ConfigV2 so a single-stream payload cannot be
// mistaken for an Agent-wide runtime snapshot.
//
// Since tcp/udp v12 a stream belongs to no website (control migration 506):
// the wire spec and its geo carry no site_id. The agent keys the stream's
// telemetry, DNS state and geo policy by the stream ID in that slot
// (ListenerV2.SiteID), so a stream is its own partition.
type StreamRuntimeSpecV2 struct {
	SchemaVersion           string                 `json:"schema_version"`
	TenantID                string                 `json:"tenant_id"`
	StreamID                string                 `json:"stream_id"`
	Revision                int64                  `json:"revision"`
	Listener                ListenerSocketV2       `json:"listener"`
	AdditionalListeners     []AdditionalListenerV2 `json:"additional_listeners,omitempty"`
	Endpoint                EndpointV2             `json:"endpoint"`
	DNS                     DNSPolicyV2            `json:"dns"`
	Geo                     GeoPolicyV2            `json:"geo"`
	ConnectTimeoutMS        int                    `json:"connect_timeout_ms"`
	ResponseTimeoutMS       int                    `json:"response_timeout_ms"`
	MaxConnectionsPerClient int                    `json:"max_connections_per_client"`
	DrainTimeoutMS          int                    `json:"drain_timeout_ms"`
	// DrainMaxMS bounds how long a worker generation retired by a reload may
	// keep serving its sessions: nil is the default (DefaultDrainMaxMS), 0 is
	// unlimited. It is omitted when nil so default releases stay byte-identical.
	DrainMaxMS            *int `json:"drain_max_ms,omitempty"`
	ProxyProtocolInbound  bool `json:"proxy_protocol_inbound"`
	ProxyProtocolOutbound bool `json:"proxy_protocol_outbound"`
	// ConfigVersionID and ConfigRevision name the configuration scope release
	// the stream belongs to when one runtime serves several scopes; telemetry
	// is attributed to it instead of the composed set's version.
	ConfigVersionID string `json:"config_version_id,omitempty"`
	ConfigRevision  int64  `json:"config_revision,omitempty"`
	// TLSPassthrough streams forward TLS unterminated and are chosen by SNI
	// (ServerNames: exact names or a leading "*." wildcard), so several can
	// share one TCP port (edgeconfig.FindPortConflicts).
	TLSPassthrough bool     `json:"tls_passthrough,omitempty"`
	ServerNames    []string `json:"server_names,omitempty"`
	// NewConnRate (tcp/udp v6) limits the connections (UDP: sessions) one
	// client may open to the stream; omitted when nil.
	NewConnRate *NewConnRateV2 `json:"new_conn_rate,omitempty"`
	// SessionLog (tcp/udp v7) writes the l4_session_v2 log (client,
	// upstream, end reason) and tracks the live TCP sessions; omitted when
	// false.
	SessionLog bool `json:"session_log,omitempty"`
	// GuardRules (tcp/udp v10) are the stream's L4 guard rules
	// (edgeconfig.L4GuardRuleV2), evaluated in preread; omitted when empty.
	GuardRules []GuardRuleV2 `json:"guard_rules,omitempty"`
	// SubscriptionLimits (SUBSCRIPTION_LIMITS v1, ADR 0012 ML-07) are the
	// market subscription's session limits, shared by its streams on the
	// node (preread counts, log releases); omitted when nil.
	SubscriptionLimits *SubscriptionLimitsV2 `json:"subscription_limits,omitempty"`
	// ListenIPv6 (tcp/udp v11, IPv6开启) also listens on [::] for each socket
	// the stream owns alone; omitted when false.
	ListenIPv6 bool `json:"listen_ipv6,omitempty"`
	// TOA (TCP only, no PROXY protocol) renders proxy_toa: the patched
	// OpenResty hands the client address to the TOA eBPF program, which
	// writes TCP option 254 to the origin. Requires CAPABILITY_NAME_L4_TOA.
	TOA bool `json:"toa,omitempty"`
	// PackageSubscriptionID (L4_PACKAGE_ATTRIBUTION v1) is the package the
	// forward belongs to at this publication; the agent stamps it on the
	// stream's session facts. Omitted for a forward without a package.
	PackageSubscriptionID string `json:"package_subscription_id,omitempty"`
}

// NewConnRateV2 is a per-client token bucket of RatePerSecond+Burst refilled
// at RatePerSecond, shared by every socket of the stream. Over the limit the
// connection is refused and, when BanSeconds > 0, the client's new
// connections to the stream are refused for that long
// (edgeconfig.L4NewConnRateV2, docs/architecture/l4-v6-fields.md).
type NewConnRateV2 struct {
	RatePerSecond int `json:"rate_per_second"`
	Burst         int `json:"burst"`
	BanSeconds    int `json:"ban_seconds"`
}

// SubscriptionLimitsV2 is edgeconfig.L4SubscriptionLimitsV2 (one contract).
type SubscriptionLimitsV2 = edgeconfig.L4SubscriptionLimitsV2

// GuardRuleV2 is edgeconfig.L4GuardRuleV2: the control plane and the agent
// share the wire contract and its validation (edgeconfig.NormalizeL4GuardRules).
type GuardRuleV2 = edgeconfig.L4GuardRuleV2

// SiteSocketsV2 hands the websites on a port the L4 runtime owns to the site
// OpenResty: plaintext to PlainSocket, TLS whose SNI is one of TLSServerNames
// (or unknown) to TLSSocket. Both are unix sockets the site OpenResty listens
// on with PROXY protocol.
type SiteSocketsV2 struct {
	Port           int      `json:"port"`
	PlainSocket    string   `json:"plain_socket,omitempty"`
	TLSSocket      string   `json:"tls_socket,omitempty"`
	TLSServerNames []string `json:"tls_server_names,omitempty"`
}

type ListenerV2 struct {
	ID                      string                 `json:"id"`
	ResourceRevision        int64                  `json:"resource_revision,omitempty"`
	TenantID                string                 `json:"tenant_id"`
	SiteID                  string                 `json:"site_id"`
	StreamID                string                 `json:"stream_id"`
	Protocol                Protocol               `json:"protocol"`
	Address                 string                 `json:"address"`
	Port                    int                    `json:"port"`
	PortEnd                 int                    `json:"port_end,omitempty"`
	AdditionalListeners     []AdditionalListenerV2 `json:"additional_listeners,omitempty"`
	Endpoint                EndpointV2             `json:"endpoint"`
	DNS                     DNSPolicyV2            `json:"dns"`
	Geo                     GeoPolicyV2            `json:"geo"`
	ConnectTimeoutMS        int                    `json:"connect_timeout_ms"`
	ResponseTimeoutMS       int                    `json:"response_timeout_ms"`
	MaxConnectionsPerClient int                    `json:"max_connections_per_client"`
	DrainTimeoutMS          int                    `json:"drain_timeout_ms"`
	DrainMaxMS              *int                   `json:"drain_max_ms,omitempty"`
	ProxyProtocolInbound    bool                   `json:"proxy_protocol_inbound"`
	ProxyProtocolOutbound   bool                   `json:"proxy_protocol_outbound"`
	ConfigVersionID         string                 `json:"config_version_id,omitempty"`
	ConfigRevision          int64                  `json:"config_revision,omitempty"`
	TLSPassthrough          bool                   `json:"tls_passthrough,omitempty"`
	ServerNames             []string               `json:"server_names,omitempty"`
	NewConnRate             *NewConnRateV2         `json:"new_conn_rate,omitempty"`
	SessionLog              bool                   `json:"session_log,omitempty"`
	GuardRules              []GuardRuleV2          `json:"guard_rules,omitempty"`
	SubscriptionLimits      *SubscriptionLimitsV2  `json:"subscription_limits,omitempty"`
	ListenIPv6              bool                   `json:"listen_ipv6,omitempty"`
	TOA                     bool                   `json:"toa,omitempty"`
	PackageSubscriptionID   string                 `json:"package_subscription_id,omitempty"`
}

type ConfigV2 struct {
	SchemaVersion string          `json:"schema_version"`
	VersionID     string          `json:"version_id"`
	Revision      int64           `json:"revision"`
	Listeners     []ListenerV2    `json:"listeners"`
	SiteSockets   []SiteSocketsV2 `json:"site_sockets,omitempty"`
	// DispatchDirectory holds the internal sockets of split ports; "" =
	// L4DispatchDirectory. Its parents must let the workers traverse them
	// (the dynamic routing node keeps the deployment root private).
	DispatchDirectory string `json:"dispatch_directory,omitempty"`
}

type CompiledConfigV2 struct {
	Config              ConfigV2
	Digest              string
	CanonicalJSON       []byte
	NginxConfig         []byte
	GeoJSON             []byte
	ResolvedAddressSets map[string][]netip.Addr
}

type DNSLookupResult struct {
	Addresses []netip.Addr
	TTL       time.Duration
	Negative  bool
}

type DNSResolver interface {
	LookupIP(context.Context, string) (DNSLookupResult, error)
}

type AddressSetHealth func(context.Context, ListenerV2, []netip.Addr) error

const (
	DNSReasonPromoted          = "L4_DNS_ADDRESS_SET_PROMOTED"
	DNSReasonFreshLKG          = "L4_DNS_ADDRESS_SET_FRESH_LKG"
	DNSReasonNegativeLKG       = "L4_DNS_NEGATIVE_ANSWER_LKG"
	DNSReasonLookupFailedLKG   = "L4_DNS_LOOKUP_FAILED_LKG"
	DNSReasonRebindingRejected = "L4_DNS_REBINDING_REJECTED_LKG"
	DNSReasonHealthRejected    = "L4_DNS_HEALTH_REJECTED_LKG"
	DNSReasonStaticAddress     = "L4_STATIC_ADDRESS_VERIFIED"
)

type ResolvedAddressSet struct {
	TenantID     string
	SiteID       string
	StreamID     string
	Revision     int64
	Host         string
	Addresses    []netip.Addr
	RefreshAfter time.Time
	StaleUntil   time.Time
	ReasonCode   string
}
