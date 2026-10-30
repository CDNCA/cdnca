package edgeconfig

import (
	"net/netip"
	"slices"
)

// DDoSProtection is the platform's node-level connection protection:
// kernel (nftables) limits every edge node applies to the
// TCP ports it serves, websites and L4 forwards alike, before OpenResty sees
// a connection. It is a platform system configuration category
// (ddos_protection) and travels in every site runtime v2 document's system
// block, so a node composing several scopes applies one value (the highest
// platform revision, SelectSiteRuntimeSystem). nil: the node installs no
// DDoS table.
//
// Every limit is per client: an IPv4 address, or an IPv6 /64 (one host owns
// a /64; counting single IPv6 addresses would let one attacker rotate
// through 2^64 of them). A field at 0 is off.
type DDoSProtection struct {
	// MaxConnectionsPerIP bounds one client's concurrent TCP connections on a
	// protected port (conntrack count).
	MaxConnectionsPerIP uint32 `json:"max_connections_per_ip"`
	// NewConnectionsPerSecond / NewConnectionsPerMinute bound one client's new
	// TCP connections (SYN) a second / a minute. Over a limit the connection
	// is dropped; with a ban time the client is also banned.
	NewConnectionsPerSecond uint32 `json:"new_connections_per_second"`
	NewConnectionsPerMinute uint32 `json:"new_connections_per_minute"`
	// RateBanSeconds bans a client over a new connection rate for this long
	// in the kernel (every protected port drops it). 0: only the excess
	// connections are dropped.
	RateBanSeconds uint32 `json:"rate_ban_seconds"`
	// MaxConnectionsPerPort bounds a protected port's concurrent TCP
	// connections from all clients (one port, not the node).
	MaxConnectionsPerPort uint32 `json:"max_connections_per_port"`
	// EmptyConnection bans clients that open connections and send nothing
	// (the slow, handshake-only flood often called a SYN flood). nil: off.
	EmptyConnection *DDoSEmptyConnection `json:"empty_connection,omitempty"`
	// AllowNetworks never count and are never banned (monitoring probes,
	// office networks, a load balancer in front of the nodes). Node
	// addresses are exempt without being listed.
	AllowNetworks []string `json:"allow_networks"`
	// CCKernelBan raises the CC engine's temporary bans of a client (rules
	// counting by client address) from OpenResty to the kernel, on the
	// banning site's ports, until the ban ends:
	//   - off: OpenResty only;
	//   - exclusive_ports: only the ports no other site or L4 forward on the
	//     node listens on, so a ban never reaches another site;
	//   - site_ports: every port of the site, shared ones included: on a
	//     shared port the client loses every site there (the platform accepts
	//     that one tenant's CC rule affects co-hosted sites).
	CCKernelBan string `json:"cc_kernel_ban"`
	// TCPFlagFilter drops malformed TCP probe and scan packets (illegal flag
	// combinations, DDoSTCPFlag*) on the protected ports; TCPFlagTypes picks
	// which. The types are kept while the switch is off (the page restores
	// them), canonical order DDoSTCPFlagTypes. Loopback is never filtered.
	TCPFlagFilter bool     `json:"tcp_flag_filter,omitempty"`
	TCPFlagTypes  []string `json:"tcp_flag_types,omitempty"`
	// DropInvalid drops packets conntrack classifies INVALID (belonging to no
	// connection and not starting one: stray ACK/RST, out of window segments)
	// on the protected ports. Loopback, node networks and the allow networks
	// (health probes) are exempt.
	DropInvalid bool `json:"drop_invalid,omitempty"`
}

// TCP flag filter types (DDoSProtection.TCPFlagTypes). Each matches the six
// classic flags (fin syn rst psh ack urg; ECE/CWR are ignored):
//   - null: none set;
//   - xmas: exactly fin psh urg;
//   - syn_fin / syn_rst: both of the pair set (never legal together);
//   - fin: exactly fin (no ack) on a packet of no existing connection. A
//     connection's normal close carries ack and is never matched; off by
//     default all the same, a bare FIN is also how some stacks probe;
//   - all: all six set. Off by default: harmless to leave to the stack, and
//     some middleboxes have been seen to emit it.
const (
	DDoSTCPFlagNull   = "null"
	DDoSTCPFlagXmas   = "xmas"
	DDoSTCPFlagSynFin = "syn_fin"
	DDoSTCPFlagSynRst = "syn_rst"
	DDoSTCPFlagFin    = "fin"
	DDoSTCPFlagAll    = "all"
)

// DDoSTCPFlagTypes is every type in canonical order.
var DDoSTCPFlagTypes = []string{DDoSTCPFlagNull, DDoSTCPFlagXmas, DDoSTCPFlagSynFin, DDoSTCPFlagSynRst, DDoSTCPFlagFin, DDoSTCPFlagAll}

// DDoSDefaultTCPFlagTypes are the types a fresh platform filters: the
// combinations no TCP stack sends. fin and all stay off (see above).
var DDoSDefaultTCPFlagTypes = []string{DDoSTCPFlagNull, DDoSTCPFlagXmas, DDoSTCPFlagSynFin, DDoSTCPFlagSynRst}

// DefaultDDoSProtection is a fresh platform's value: no connection limit,
// the default TCP flag types filtered and conntrack INVALID dropped.
func DefaultDDoSProtection() DDoSProtection {
	return DDoSProtection{AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff, TCPFlagFilter: true,
		TCPFlagTypes: slices.Clone(DDoSDefaultTCPFlagTypes), DropInvalid: true}
}

// FiltersTCPFlag reports whether the filter is on for kind.
func (value DDoSProtection) FiltersTCPFlag(kind string) bool {
	return value.TCPFlagFilter && slices.Contains(value.TCPFlagTypes, kind)
}

// CC kernel ban modes.
const (
	CCKernelBanOff            = "off"
	CCKernelBanExclusivePorts = "exclusive_ports"
	CCKernelBanSitePorts      = "site_ports"
)

// SiteRuntimeDDoS is DDoS protection as a v2 document carries it: the
// platform setting and the platform's node addresses at publication (node to
// node traffic, L1 to L2 above all, is never limited or banned). A node
// composing several scopes exempts the union of their node networks.
type SiteRuntimeDDoS struct {
	Protection   DDoSProtection `json:"protection"`
	NodeNetworks []string       `json:"node_networks"`
}

// DDoSMaxNodeNetworks bounds SiteRuntimeDDoS.NodeNetworks.
const DDoSMaxNodeNetworks = 30_000

// Validate requires canonical protection and node networks.
func (value SiteRuntimeDDoS) Validate() error {
	if value.Protection.Validate() != nil || value.NodeNetworks == nil || len(value.NodeNetworks) > DDoSMaxNodeNetworks {
		return ErrInvalidConfig
	}
	normalized, err := normalizeNetworks(value.NodeNetworks, DDoSMaxNodeNetworks)
	if err != nil || !slices.Equal(normalized, value.NodeNetworks) {
		return ErrInvalidConfig
	}
	return nil
}

// NewSiteRuntimeDDoS builds the canonical document value.
func NewSiteRuntimeDDoS(protection DDoSProtection, nodeNetworks []string) (SiteRuntimeDDoS, error) {
	normalized, err := NormalizeDDoSProtection(protection)
	if err != nil {
		return SiteRuntimeDDoS{}, err
	}
	networks, err := normalizeNetworks(nodeNetworks, DDoSMaxNodeNetworks)
	if err != nil {
		return SiteRuntimeDDoS{}, err
	}
	return SiteRuntimeDDoS{Protection: normalized, NodeNetworks: networks}, nil
}

// DDoSEmptyConnection: a connection established for IdleSeconds without one
// byte from the client is empty. A client with Threshold empty connections
// within WindowSeconds is banned for BanSeconds on every protected port and
// its empty connections are closed.
type DDoSEmptyConnection struct {
	IdleSeconds   uint32 `json:"idle_seconds"`
	Threshold     uint32 `json:"threshold"`
	WindowSeconds uint32 `json:"window_seconds"`
	BanSeconds    uint32 `json:"ban_seconds"`
}

// DDoS protection bounds (control plane and node validate the same).
const (
	DDoSMaxConnectionsPerIPLimit   = 1_000_000
	DDoSMaxNewConnectionsPerSecond = 1_000_000
	DDoSMaxNewConnectionsPerMinute = 60_000_000
	DDoSMaxBanSeconds              = 7 * 86400
	DDoSMaxConnectionsPerPortLimit = 10_000_000
	DDoSMaxAllowNetworks           = 256
	DDoSMinEmptyIdleSeconds        = 5
	DDoSMaxEmptyIdleSeconds        = 600
	DDoSMinEmptyThreshold          = 3
	DDoSMaxEmptyThreshold          = 10_000
	DDoSMinEmptyWindowSeconds      = 10
	DDoSMaxEmptyWindowSeconds      = 3600
)

// Validate requires the canonical form NormalizeDDoSProtection returns.
func (value DDoSProtection) Validate() error {
	normalized, err := NormalizeDDoSProtection(value)
	if err != nil || !slices.Equal(normalized.AllowNetworks, value.AllowNetworks) ||
		!slices.Equal(normalized.TCPFlagTypes, value.TCPFlagTypes) {
		return ErrInvalidConfig
	}
	return nil
}

// Active reports whether nodes need the setting at all: a limit, or CC bans
// raised to the kernel.
func (value DDoSProtection) Active() bool {
	return value.Enabled() || value.CCKernelBan != "" && value.CCKernelBan != CCKernelBanOff
}

// Enabled reports whether any limit or packet filter is on (the DDoS table
// is installed).
func (value DDoSProtection) Enabled() bool {
	return value.MaxConnectionsPerIP != 0 || value.NewConnectionsPerSecond != 0 || value.NewConnectionsPerMinute != 0 ||
		value.MaxConnectionsPerPort != 0 || value.EmptyConnection != nil || value.TCPFlagFilter || value.DropInvalid
}

// NormalizeDDoSProtection checks the bounds and returns the canonical value:
// allow networks as masked prefixes, sorted, without duplicates; TCP flag
// types in canonical order, without duplicates (nil when none). The filter
// on needs a type.
func NormalizeDDoSProtection(value DDoSProtection) (DDoSProtection, error) {
	if value.MaxConnectionsPerIP > DDoSMaxConnectionsPerIPLimit ||
		value.NewConnectionsPerSecond > DDoSMaxNewConnectionsPerSecond ||
		value.NewConnectionsPerMinute > DDoSMaxNewConnectionsPerMinute ||
		value.RateBanSeconds > DDoSMaxBanSeconds ||
		value.MaxConnectionsPerPort > DDoSMaxConnectionsPerPortLimit ||
		// A ban needs a rate that triggers it.
		value.RateBanSeconds != 0 && value.NewConnectionsPerSecond == 0 && value.NewConnectionsPerMinute == 0 ||
		value.AllowNetworks == nil || len(value.AllowNetworks) > DDoSMaxAllowNetworks ||
		value.CCKernelBan != CCKernelBanOff && value.CCKernelBan != CCKernelBanExclusivePorts && value.CCKernelBan != CCKernelBanSitePorts {
		return DDoSProtection{}, ErrInvalidConfig
	}
	if empty := value.EmptyConnection; empty != nil {
		if empty.IdleSeconds < DDoSMinEmptyIdleSeconds || empty.IdleSeconds > DDoSMaxEmptyIdleSeconds ||
			empty.Threshold < DDoSMinEmptyThreshold || empty.Threshold > DDoSMaxEmptyThreshold ||
			empty.WindowSeconds < DDoSMinEmptyWindowSeconds || empty.WindowSeconds > DDoSMaxEmptyWindowSeconds ||
			empty.BanSeconds < 1 || empty.BanSeconds > DDoSMaxBanSeconds {
			return DDoSProtection{}, ErrInvalidConfig
		}
		copied := *empty
		value.EmptyConnection = &copied
	}
	var types []string
	for _, kind := range DDoSTCPFlagTypes {
		if slices.Contains(value.TCPFlagTypes, kind) {
			types = append(types, kind)
		}
	}
	for _, kind := range value.TCPFlagTypes {
		if !slices.Contains(DDoSTCPFlagTypes, kind) {
			return DDoSProtection{}, ErrInvalidConfig
		}
	}
	if value.TCPFlagFilter && len(types) == 0 {
		return DDoSProtection{}, ErrInvalidConfig
	}
	value.TCPFlagTypes = types
	networks, err := normalizeNetworks(value.AllowNetworks, DDoSMaxAllowNetworks)
	if err != nil {
		return DDoSProtection{}, err
	}
	value.AllowNetworks = networks
	return value, nil
}

// normalizeNetworks parses addresses and prefixes into masked prefixes,
// sorted, without duplicates (an address is its full-length prefix).
func normalizeNetworks(values []string, limit int) ([]string, error) {
	if values == nil || len(values) > limit {
		return nil, ErrInvalidConfig
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			address, addressErr := netip.ParseAddr(raw)
			if addressErr != nil || address.Zone() != "" {
				return nil, ErrInvalidConfig
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return nil, ErrInvalidConfig
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	slices.SortFunc(prefixes, func(left, right netip.Prefix) int {
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison
		}
		return left.Bits() - right.Bits()
	})
	prefixes = slices.Compact(prefixes)
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	return result, nil
}
