package edgeconfig

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	L4RuntimeV2ArtifactPath = "l4-runtime.v2.json"
	l4RuntimeV2Schema       = "cdnca.edge.l4/v2"
	l4StreamSetV2Schema     = "cdnca.edge.l4-stream-set/v2"
)

// PortEnd (G4-c #4, tcp/udp v9) makes a listener the port range
// Port..PortEnd (at most L4PortRangeMax ports); 0 is the single Port.
type L4ListenerV2 struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	PortEnd  int    `json:"port_end,omitempty"`
}

type L4AdditionalListenerV2 struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	PortEnd  int    `json:"port_end,omitempty"`
}

// FollowPort (G4-c #4, tcp/udp v9) connects to the origin on the port the
// client connected to; Port then equals the primary listener's Port.
//
// Origins (tcp/udp v11, 源站列表) lists several origin addresses on Port, each
// with a weight and an up/down state; Address is then Origins[0].Address and
// Host is empty (several origins are IP addresses). Balance "ip_hash" (定源)
// keeps one client on one origin; omitted it is round robin by weight.
type L4EndpointV2 struct {
	Address    string       `json:"address,omitempty"`
	Host       string       `json:"host,omitempty"`
	Port       int          `json:"port"`
	FollowPort bool         `json:"follow_port,omitempty"`
	Origins    []L4OriginV2 `json:"origins,omitempty"`
	Balance    string       `json:"balance,omitempty"`
}

// L4OriginV2 is one origin of a multi-origin endpoint (tcp/udp v11).
type L4OriginV2 struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
	Down    bool   `json:"down,omitempty"`
}

const (
	// L4OriginsMax bounds an endpoint's origins; L4OriginWeightMax a weight.
	L4OriginsMax      = 64
	L4OriginWeightMax = 100
	L4BalanceIPHash   = "ip_hash"
)

// NormalizeL4Origins checks a multi-origin endpoint: IP addresses (unique,
// unmapped, not unspecified or multicast), weights 1..L4OriginWeightMax and at
// least one origin up. Order is kept (the first is Endpoint.Address).
func NormalizeL4Origins(origins []L4OriginV2) ([]L4OriginV2, error) {
	if len(origins) == 0 {
		return nil, nil
	}
	if len(origins) > L4OriginsMax {
		return nil, ErrInvalidConfig
	}
	result := make([]L4OriginV2, len(origins))
	seen := make(map[netip.Addr]struct{}, len(origins))
	up := false
	for index, origin := range origins {
		address, err := netip.ParseAddr(origin.Address)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() ||
			origin.Weight < 1 || origin.Weight > L4OriginWeightMax {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[address]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[address] = struct{}{}
		up = up || !origin.Down
		result[index] = L4OriginV2{Address: address.String(), Weight: origin.Weight, Down: origin.Down}
	}
	if !up {
		return nil, ErrInvalidConfig
	}
	return result, nil
}

// L4OriginPoolUsed reports whether a stream uses origins, ip_hash or IPv6
// listening (tcp/udp v11).
func L4OriginPoolUsed(stream L4StreamRuntimeV2) bool {
	return len(stream.Endpoint.Origins) != 0 || stream.Endpoint.Balance != "" || stream.ListenIPv6
}

// L4PortRangeMax bounds the ports of one listener range.
const L4PortRangeMax = 1000

// L4RangeProtectedPorts are the node's own ports (websites 80/443, the agent
// health port 18080 and certificate runtime 18443): a port range may not
// cover them.
var L4RangeProtectedPorts = []int{80, 443, 18080, 18443}

// ValidL4PortRange checks port..portEnd (portEnd 0: the single port) and
// returns the last port of the range.
func ValidL4PortRange(port, portEnd int) (int, bool) {
	if port < 1 || port > 65535 {
		return 0, false
	}
	if portEnd == 0 {
		return port, true
	}
	if portEnd <= port || portEnd > 65535 || portEnd-port+1 > L4PortRangeMax {
		return 0, false
	}
	for _, protected := range L4RangeProtectedPorts {
		if protected >= port && protected <= portEnd {
			return 0, false
		}
	}
	return portEnd, true
}

// L4PortRangesUsed reports whether a stream has a port range or follows the
// client's port to the origin (tcp/udp v9).
func L4PortRangesUsed(stream L4StreamRuntimeV2) bool {
	if stream.Listener.PortEnd != 0 || stream.Endpoint.FollowPort {
		return true
	}
	for _, listener := range stream.AdditionalListeners {
		if listener.PortEnd != 0 {
			return true
		}
	}
	return false
}

type L4DNSPolicyV2 struct {
	PositiveMinTTLSeconds int64 `json:"positive_min_ttl_seconds"`
	PositiveMaxTTLSeconds int64 `json:"positive_max_ttl_seconds"`
	NegativeTTLSeconds    int64 `json:"negative_ttl_seconds"`
	StaleIfErrorSeconds   int64 `json:"stale_if_error_seconds"`
	AllowPrivateAddresses bool  `json:"allow_private_addresses"`
}

type L4RegionCIDRsV2 struct {
	Region string   `json:"region"`
	CIDRs  []string `json:"cidrs"`
}

type L4GeoPolicyV2 struct {
	Enabled             bool              `json:"enabled"`
	TenantID            string            `json:"tenant_id"`
	StreamID            string            `json:"stream_id"`
	Revision            int64             `json:"revision"`
	UnknownRegionAction string            `json:"unknown_region_action"`
	TrustedProxyCIDRs   []string          `json:"trusted_proxy_cidrs"`
	BlockedRegions      []string          `json:"blocked_regions"`
	RegionCIDRs         []L4RegionCIDRsV2 `json:"region_cidrs"`
}

type L4StreamRuntimeV2 struct {
	SchemaVersion           string                   `json:"schema_version"`
	TenantID                string                   `json:"tenant_id"`
	StreamID                string                   `json:"stream_id"`
	Revision                int64                    `json:"revision"`
	Listener                L4ListenerV2             `json:"listener"`
	AdditionalListeners     []L4AdditionalListenerV2 `json:"additional_listeners,omitempty"`
	Endpoint                L4EndpointV2             `json:"endpoint"`
	DNS                     L4DNSPolicyV2            `json:"dns"`
	Geo                     L4GeoPolicyV2            `json:"geo"`
	ConnectTimeoutMS        int                      `json:"connect_timeout_ms"`
	ResponseTimeoutMS       int                      `json:"response_timeout_ms"`
	MaxConnectionsPerClient int                      `json:"max_connections_per_client"`
	DrainTimeoutMS          int                      `json:"drain_timeout_ms"`
	// DrainMaxMS bounds how long sessions of a worker generation retired by a
	// reload may keep running (0: unlimited; unset: the agent default, 24 h).
	// Only tcp/udp v5 agents know it; it is omitted when unset.
	DrainMaxMS            *int `json:"drain_max_ms,omitempty"`
	ProxyProtocolInbound  bool `json:"proxy_protocol_inbound"`
	ProxyProtocolOutbound bool `json:"proxy_protocol_outbound"`
	// TLSPassthrough streams forward TLS unterminated and are picked by SNI
	// (ServerNames: exact names or a leading "*." wildcard), so several can
	// share one TCP port; see FindPortConflicts.
	// Both are omitted when unset to keep existing artifacts byte-identical.
	TLSPassthrough bool     `json:"tls_passthrough,omitempty"`
	ServerNames    []string `json:"server_names,omitempty"`
	// 1.0.35 fields, in this order (docs/architecture/l4-v6-fields.md). Each
	// is omitted when unset and gated by the capability version noted.
	// G4-a #3, tcp/udp v6: per-client new connection rate.
	NewConnRate *L4NewConnRateV2 `json:"new_conn_rate,omitempty"`
	// G4-b #6, tcp/udp v7: per-session access log with the client, upstream
	// and end reason (refused sessions included), reported through the L4
	// telemetry spool.
	SessionLog bool `json:"session_log,omitempty"`
	// G4-d #8, tcp/udp v10: L4 guard rules (first packet / SNI / client IP
	// / geo conditions; drop, ban, allow), evaluated in order in preread.
	GuardRules []L4GuardRuleV2 `json:"guard_rules,omitempty"`
	// (G4-c #4, tcp/udp v9: port_end on L4ListenerV2/L4AdditionalListenerV2,
	// follow_port on L4EndpointV2.)
	// ADR 0012 ML-07, SUBSCRIPTION_LIMITS v1: the market subscription's
	// session limits on this node.
	SubscriptionLimits *L4SubscriptionLimitsV2 `json:"subscription_limits,omitempty"`
	// tcp/udp v11 (IPv6开启): the node also listens on [::] for each of the
	// stream's sockets it owns alone (a node without IPv6 listens on IPv4 only).
	ListenIPv6 bool `json:"listen_ipv6,omitempty"`
	// G5, tcp v8 + L4_TOA v1: TOA streams (TCP only) carry the IPv4 client
	// address to the origin in TCP option 254 (proxy_toa); excludes PROXY
	// protocol both ways.
	TOA bool `json:"toa,omitempty"`
	// L4_PACKAGE_ATTRIBUTION v1: the package subscription the
	// forward belongs to at this publication. The node stamps it on every
	// session fact, so a session's bytes stay with the package it ran under
	// after the forward moves to another. Set by the publication from
	// l4_forwards (never in the stored intent); omitted for a forward without
	// a package.
	PackageSubscriptionID string `json:"package_subscription_id,omitempty"`
}

// L4PackageAttributionCapability / L4PackageAttributionAPIVersion: the site
// runtime document capability of CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION.
const (
	L4PackageAttributionCapability        = "l4_package_attribution"
	L4PackageAttributionAPIVersion uint32 = 1
)

// L4NewConnRateV2 limits how many connections (UDP: sessions) one client IP
// may open to a stream: a token bucket of RatePerSecond+Burst refilled at
// RatePerSecond. Over the limit the connection is refused and, when
// BanSeconds > 0, the client's new connections to the stream are refused for
// that long. Requires tcp/udp v6.
type L4NewConnRateV2 struct {
	RatePerSecond int `json:"rate_per_second"`
	Burst         int `json:"burst"`
	BanSeconds    int `json:"ban_seconds"`
}

// Bounds of L4NewConnRateV2.
const (
	L4NewConnRateMax       = 100_000
	L4NewConnBurstMax      = 100_000
	L4NewConnBanSecondsMax = 86_400
)

// ValidL4NewConnRate accepts an unset limit or one within the bounds above.
func ValidL4NewConnRate(value *L4NewConnRateV2) bool {
	return value == nil || (value.RatePerSecond >= 1 && value.RatePerSecond <= L4NewConnRateMax &&
		value.Burst >= 0 && value.Burst <= L4NewConnBurstMax &&
		value.BanSeconds >= 0 && value.BanSeconds <= L4NewConnBanSecondsMax)
}

// L4DrainMaxMSMax bounds drain_max_ms (7 days).
const L4DrainMaxMSMax = 7 * 86_400_000

// ValidL4DrainMaxMS accepts an unset drain limit, 0 (unlimited), or 1 s to
// L4DrainMaxMSMax.
func ValidL4DrainMaxMS(value *int) bool {
	return value == nil || *value == 0 || (*value >= 1_000 && *value <= L4DrainMaxMSMax)
}

// L4ServerNamesMax bounds the SNI list of one TLS passthrough stream.
const L4ServerNamesMax = 32

type l4StreamSetV2 struct {
	SchemaVersion string              `json:"schema_version"`
	VersionID     string              `json:"version_id"`
	Revision      int64               `json:"revision"`
	Streams       []L4StreamRuntimeV2 `json:"streams"`
}

// normalizeL4StreamsV2 validates v2 streams. occupiedPorts and
// occupiedListeners are what the streams may not touch. Unless shared, v2
// sockets are also added to occupiedListeners so no two streams share one;
// shared callers check sharing with FindPortConflicts instead.
func normalizeL4StreamsV2(tenantID string, values []L4StreamRuntimeV2, occupiedPorts map[uint16]Protocol,
	occupiedListeners, occupiedIDs map[string]struct{}, shared bool) ([]L4StreamRuntimeV2, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if !uuidPattern.MatchString(tenantID) {
		return nil, ErrInvalidConfig
	}
	result := append([]L4StreamRuntimeV2(nil), values...)
	for index := range result {
		if result[index].NewConnRate != nil {
			rate := *result[index].NewConnRate
			result[index].NewConnRate = &rate
		}
		if result[index].SubscriptionLimits != nil {
			limits := *result[index].SubscriptionLimits
			result[index].SubscriptionLimits = &limits
		}
	}
	for _, item := range result {
		if _, exists := occupiedIDs[item.StreamID]; exists {
			return nil, ErrInvalidConfig
		}
		occupiedIDs[item.StreamID] = struct{}{}
	}
	// Listen directives so far (a port range is one), against the 256 limit.
	baseline, sockets := len(occupiedListeners), 0
	for index := range result {
		item := &result[index]
		_, validListener := ValidL4PortRange(item.Listener.Port, item.Listener.PortEnd)
		if item.SchemaVersion != l4RuntimeV2Schema || item.TenantID != tenantID ||
			!uuidPattern.MatchString(item.StreamID) || item.Revision < 1 || item.Revision > 1<<53-1 ||
			(item.PackageSubscriptionID != "" && (!uuidPattern.MatchString(item.PackageSubscriptionID) ||
				item.PackageSubscriptionID != strings.ToLower(item.PackageSubscriptionID) ||
				item.PackageSubscriptionID == "00000000-0000-0000-0000-000000000000")) ||
			len(item.AdditionalListeners) > 63 ||
			(item.Listener.Protocol != string(StreamProtocolTCP) && item.Listener.Protocol != string(StreamProtocolUDP)) ||
			item.Listener.Address != "*" || !validListener ||
			(item.Endpoint.FollowPort && item.Endpoint.Port != item.Listener.Port) ||
			item.Endpoint.Port < 1 || item.Endpoint.Port > 65535 || (item.Endpoint.Address == "") == (item.Endpoint.Host == "") ||
			item.ConnectTimeoutMS < 50 || item.ConnectTimeoutMS > 30000 || item.ResponseTimeoutMS < 100 || item.ResponseTimeoutMS > 600000 ||
			item.MaxConnectionsPerClient < 1 || item.MaxConnectionsPerClient > 10000 || item.DrainTimeoutMS != 30000 ||
			!ValidL4DrainMaxMS(item.DrainMaxMS) || !ValidL4NewConnRate(item.NewConnRate) ||
			!ValidL4SubscriptionLimits(item.SubscriptionLimits) ||
			(item.Listener.Protocol == string(StreamProtocolUDP) && (item.ProxyProtocolInbound || item.ProxyProtocolOutbound)) ||
			(item.TOA && (item.Listener.Protocol != string(StreamProtocolTCP) || item.ProxyProtocolInbound || item.ProxyProtocolOutbound)) {
			return nil, ErrInvalidConfig
		}
		// Every port of a range is claimed; a range is one listen directive.
		own := map[string]struct{}{}
		ranged := false
		claim := func(protocol string, port, portEnd int) bool {
			last, valid := ValidL4PortRange(port, portEnd)
			if !valid {
				return false
			}
			ranged = ranged || portEnd != 0
			sockets++
			for current := port; current <= last; current++ {
				key := protocol + "\x00" + strconv.Itoa(current)
				_, busyPort := occupiedPorts[uint16(current)]
				_, busyListener := occupiedListeners[key]
				_, mine := own[key]
				if busyPort || busyListener || mine {
					return false
				}
				own[key] = struct{}{}
			}
			return true
		}
		if !claim(item.Listener.Protocol, item.Listener.Port, item.Listener.PortEnd) {
			return nil, ErrInvalidConfig
		}
		item.AdditionalListeners = append([]L4AdditionalListenerV2(nil), item.AdditionalListeners...)
		for _, socket := range item.AdditionalListeners {
			if !uuidPattern.MatchString(socket.ID) || socket.Address != "*" ||
				(socket.Protocol != string(StreamProtocolTCP) && socket.Protocol != string(StreamProtocolUDP)) ||
				(socket.Protocol == string(StreamProtocolUDP) && (item.ProxyProtocolInbound || item.ProxyProtocolOutbound || item.TOA)) {
				return nil, ErrInvalidConfig
			}
			if _, exists := occupiedIDs[socket.ID]; exists {
				return nil, ErrInvalidConfig
			}
			occupiedIDs[socket.ID] = struct{}{}
			if !claim(socket.Protocol, socket.Port, socket.PortEnd) {
				return nil, ErrInvalidConfig
			}
		}
		// A range is never split by SNI.
		if ranged && item.TLSPassthrough {
			return nil, ErrInvalidConfig
		}
		if !shared {
			for key := range own {
				occupiedListeners[key] = struct{}{}
			}
		}
		if baseline+sockets > 256 {
			return nil, ErrInvalidConfig
		}
		sort.Slice(item.AdditionalListeners, func(i, j int) bool { return item.AdditionalListeners[i].ID < item.AdditionalListeners[j].ID })
		if item.Endpoint.Balance != "" && item.Endpoint.Balance != L4BalanceIPHash {
			return nil, ErrInvalidConfig
		}
		if len(item.Endpoint.Origins) != 0 {
			origins, err := NormalizeL4Origins(item.Endpoint.Origins)
			if err != nil || item.Endpoint.FollowPort || item.Endpoint.Host != "" || item.Endpoint.Address != origins[0].Address {
				return nil, ErrInvalidConfig
			}
			item.Endpoint.Origins = origins
		}
		if item.Endpoint.Address != "" {
			address, err := netip.ParseAddr(item.Endpoint.Address)
			if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || item.DNS != (L4DNSPolicyV2{}) {
				return nil, ErrInvalidConfig
			}
			item.Endpoint.Address = address.Unmap().String()
		} else {
			host, err := normalizeDNSName(item.Endpoint.Host, true)
			if err != nil || item.DNS.PositiveMinTTLSeconds < 1 || item.DNS.PositiveMaxTTLSeconds < item.DNS.PositiveMinTTLSeconds ||
				item.DNS.PositiveMaxTTLSeconds > 86400 || item.DNS.NegativeTTLSeconds < 1 || item.DNS.NegativeTTLSeconds > 3600 ||
				item.DNS.StaleIfErrorSeconds < item.DNS.PositiveMaxTTLSeconds || item.DNS.StaleIfErrorSeconds > 86400 || item.DNS.AllowPrivateAddresses {
				return nil, ErrInvalidConfig
			}
			item.Endpoint.Host = host
		}
		if err := normalizeL4GeoV2(item.TenantID, item.StreamID, item.Revision, &item.Geo); err != nil {
			return nil, err
		}
		if item.ProxyProtocolInbound != (item.Geo.Enabled && len(item.Geo.TrustedProxyCIDRs) != 0) {
			return nil, ErrInvalidConfig
		}
		serverNames, err := normalizeL4ServerNames(item)
		if err != nil {
			return nil, err
		}
		item.ServerNames = serverNames
		guardRules, err := NormalizeL4GuardRules(item.GuardRules, item.TLSPassthrough)
		if err != nil {
			return nil, err
		}
		item.GuardRules = guardRules
	}
	sort.Slice(result, func(i, j int) bool { return result[i].StreamID < result[j].StreamID })
	return result, nil
}

// normalizeL4ServerName accepts an exact host name or a leading wildcard
// ("*.example.com", nginx map hostnames semantics: exact names win). Only the
// leftmost label may be "*", and the rest needs at least two labels. Values
// must already be canonical (lower case, no trailing dot).
func normalizeL4ServerName(value string) (string, error) {
	base := strings.TrimPrefix(value, "*.")
	name, err := normalizeDNSName(base, true)
	if err != nil || name != base {
		return "", ErrInvalidConfig
	}
	return value, nil
}

// normalizeL4ServerNames returns the sorted SNI list of a TLS passthrough
// stream. Passthrough needs TCP on every listener and at least one server
// name; a plain stream carries none.
func normalizeL4ServerNames(item *L4StreamRuntimeV2) ([]string, error) {
	if !item.TLSPassthrough {
		if len(item.ServerNames) != 0 {
			return nil, ErrInvalidConfig
		}
		return nil, nil
	}
	if item.Listener.Protocol != string(StreamProtocolTCP) || len(item.ServerNames) == 0 || len(item.ServerNames) > L4ServerNamesMax {
		return nil, ErrInvalidConfig
	}
	for _, socket := range item.AdditionalListeners {
		if socket.Protocol != string(StreamProtocolTCP) {
			return nil, ErrInvalidConfig
		}
	}
	names := make([]string, 0, len(item.ServerNames))
	seen := make(map[string]struct{}, len(item.ServerNames))
	for _, value := range item.ServerNames {
		name, err := normalizeL4ServerName(value)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func normalizeL4GeoV2(tenantID, streamID string, revision int64, policy *L4GeoPolicyV2) error {
	if policy.TenantID != tenantID || policy.StreamID != streamID || policy.Revision != revision {
		return ErrInvalidConfig
	}
	if !policy.Enabled {
		if policy.UnknownRegionAction != "allow" || len(policy.TrustedProxyCIDRs) != 0 || len(policy.BlockedRegions) != 0 || len(policy.RegionCIDRs) != 0 {
			return ErrInvalidConfig
		}
		return nil
	}
	if policy.UnknownRegionAction != "allow" && policy.UnknownRegionAction != "block" {
		return ErrInvalidConfig
	}
	for _, cidr := range policy.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return ErrInvalidConfig
		}
	}
	regions := make(map[string]struct{}, len(policy.RegionCIDRs))
	for _, region := range policy.RegionCIDRs {
		if region.Region == "" || len(region.CIDRs) == 0 {
			return ErrInvalidConfig
		}
		regions[region.Region] = struct{}{}
		for _, cidr := range region.CIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return ErrInvalidConfig
			}
		}
	}
	for _, region := range policy.BlockedRegions {
		if _, exists := regions[region]; !exists {
			return ErrInvalidConfig
		}
	}
	return nil
}

func canonicalL4StreamSetV2(versionID string, revision uint64, streams []L4StreamRuntimeV2) ([]byte, error) {
	if !versionPattern.MatchString(versionID) || revision == 0 || revision > 1<<53-1 || len(streams) == 0 {
		return nil, ErrInvalidConfig
	}
	content, err := json.Marshal(l4StreamSetV2{SchemaVersion: l4StreamSetV2Schema, VersionID: versionID, Revision: int64(revision), Streams: streams})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return append(content, '\n'), nil
}
