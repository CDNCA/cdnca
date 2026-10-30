package l4runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

var geoRegionPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

var alwaysForbiddenAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// AggregateStreamRuntimeSpecsV2 builds the runtime configuration of specs.
// sites hands website traffic on ports the streams share with websites to
// the site OpenResty (a composed or shared-port node).
func AggregateStreamRuntimeSpecsV2(versionID string, revision int64, specs []StreamRuntimeSpecV2, sites ...SiteSocketsV2) (ConfigV2, error) {
	config := ConfigV2{SchemaVersion: SchemaVersionV2, VersionID: versionID, Revision: revision, Listeners: make([]ListenerV2, 0, len(specs))}
	if len(sites) != 0 {
		config.SiteSockets = append([]SiteSocketsV2(nil), sites...)
	}
	for _, spec := range specs {
		if spec.SchemaVersion != SchemaVersionV2 || spec.Revision < 1 || spec.Revision > maxExactJSONInteger {
			return ConfigV2{}, ErrInvalidConfig
		}
		for _, socket := range spec.AdditionalListeners {
			if socket.Address != "*" {
				return ConfigV2{}, ErrInvalidConfig
			}
		}
		resourceRevision := spec.Revision
		if resourceRevision == revision {
			resourceRevision = 0 // Preserve historical aggregate bytes and digests.
		}
		// v12: the stream is its own partition (no website, see StreamRuntimeSpecV2).
		geo := spec.Geo
		geo.SiteID = spec.StreamID
		config.Listeners = append(config.Listeners, ListenerV2{
			ID: spec.StreamID, TenantID: spec.TenantID, SiteID: spec.StreamID, StreamID: spec.StreamID,
			ResourceRevision: resourceRevision,
			Protocol:         spec.Listener.Protocol, Address: spec.Listener.Address, Port: spec.Listener.Port,
			PortEnd:             spec.Listener.PortEnd,
			AdditionalListeners: spec.AdditionalListeners,
			Endpoint:            spec.Endpoint, DNS: spec.DNS, Geo: geo,
			ConnectTimeoutMS: spec.ConnectTimeoutMS, ResponseTimeoutMS: spec.ResponseTimeoutMS,
			MaxConnectionsPerClient: spec.MaxConnectionsPerClient, DrainTimeoutMS: spec.DrainTimeoutMS,
			DrainMaxMS:           cloneDrainMaxMS(spec.DrainMaxMS),
			ProxyProtocolInbound: spec.ProxyProtocolInbound, ProxyProtocolOutbound: spec.ProxyProtocolOutbound,
			ConfigVersionID: spec.ConfigVersionID, ConfigRevision: spec.ConfigRevision,
			TLSPassthrough: spec.TLSPassthrough, ServerNames: spec.ServerNames,
			NewConnRate: cloneNewConnRate(spec.NewConnRate), SessionLog: spec.SessionLog,
			GuardRules: spec.GuardRules, TOA: spec.TOA, SubscriptionLimits: cloneSubscriptionLimits(spec.SubscriptionLimits),
			ListenIPv6: spec.ListenIPv6, PackageSubscriptionID: spec.PackageSubscriptionID,
		})
	}
	return normalizeConfigV2(config)
}

func CanonicalV2(config ConfigV2) ([]byte, error) {
	normalized, err := normalizeConfigV2(config)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return append(encoded, '\n'), nil
}

func normalizeConfigV2(config ConfigV2) (ConfigV2, error) {
	if config.SchemaVersion != SchemaVersionV2 || !identifierPattern.MatchString(config.VersionID) ||
		config.Revision < 1 || config.Revision > maxExactJSONInteger || len(config.Listeners) == 0 || len(config.Listeners) > maxListeners {
		return ConfigV2{}, ErrInvalidConfig
	}
	normalized := ConfigV2{SchemaVersion: SchemaVersionV2, VersionID: config.VersionID, Revision: config.Revision, Listeners: make([]ListenerV2, 0, len(config.Listeners))}
	identities := make(map[string]struct{}, len(config.Listeners))
	socketIDs := make(map[string]struct{})
	var sockets []ListenerV2
	for _, listener := range config.Listeners {
		normalizedListener, err := normalizeListenerV2(config.Revision, listener)
		if err != nil {
			return ConfigV2{}, err
		}
		identity := normalizedListener.TenantID + "\x00" + normalizedListener.SiteID + "\x00" + normalizedListener.StreamID
		if _, duplicate := identities[identity]; duplicate {
			return ConfigV2{}, ErrInvalidConfig
		}
		identities[identity] = struct{}{}
		for _, socket := range listenerSocketsV2(normalizedListener) {
			if _, duplicate := socketIDs[strings.ToLower(socket.ID)]; duplicate {
				return ConfigV2{}, ErrInvalidConfig
			}
			socketIDs[strings.ToLower(socket.ID)] = struct{}{}
			physical := normalizedListener
			physical = physical.onSocket(socket)
			sockets = append(sockets, physical)
			if len(sockets) > maxListeners {
				return ConfigV2{}, ErrInvalidConfig
			}
		}
		normalized.Listeners = append(normalized.Listeners, normalizedListener)
	}
	sort.Slice(normalized.Listeners, func(i, j int) bool {
		left, right := normalized.Listeners[i], normalized.Listeners[j]
		if left.TenantID != right.TenantID {
			return left.TenantID < right.TenantID
		}
		if left.SiteID != right.SiteID {
			return left.SiteID < right.SiteID
		}
		return left.StreamID < right.StreamID
	})
	sites, err := normalizeSiteSocketsV2(config.SiteSockets)
	if err != nil {
		return ConfigV2{}, err
	}
	normalized.SiteSockets = sites
	if !validDispatchDirectory(config.DispatchDirectory) {
		return ConfigV2{}, ErrInvalidConfig
	}
	normalized.DispatchDirectory = config.DispatchDirectory
	if _, err := planSharedSocketsV2(sockets, sites, normalized.dispatchDirectory()); err != nil {
		return ConfigV2{}, err
	}
	return normalized, nil
}

func normalizeListenerV2(revision int64, listener ListenerV2) (ListenerV2, error) {
	if listener.ResourceRevision < 0 || listener.ResourceRevision > maxExactJSONInteger || len(listener.AdditionalListeners) > 63 {
		return ListenerV2{}, ErrInvalidConfig
	}
	resourceRevision := listener.ResourceRevision
	if resourceRevision == revision {
		resourceRevision = 0
	}
	if listener.ResourceRevision != 0 {
		revision = listener.ResourceRevision
	}
	serverNames, err := normalizeL4ServerNamesV2(listener)
	if err != nil {
		return ListenerV2{}, err
	}
	if (listener.ConfigVersionID == "") != (listener.ConfigRevision == 0) ||
		listener.ConfigVersionID != "" && (!identifierPattern.MatchString(listener.ConfigVersionID) ||
			!safeTelemetryPathComponent(listener.ConfigVersionID) || listener.ConfigRevision < 1 || listener.ConfigRevision > maxExactJSONInteger) {
		return ListenerV2{}, ErrInvalidConfig
	}
	if !validUUID(listener.TenantID) || !validUUID(listener.SiteID) || !validUUID(listener.StreamID) || listener.ID != listener.StreamID ||
		(listener.PackageSubscriptionID != "" && (!validUUID(listener.PackageSubscriptionID) ||
			listener.PackageSubscriptionID != strings.ToLower(listener.PackageSubscriptionID) ||
			listener.PackageSubscriptionID == "00000000-0000-0000-0000-000000000000")) ||
		(listener.Protocol != ProtocolTCP && listener.Protocol != ProtocolUDP) || !validPortRangeV2(listener.Port, listener.PortEnd) ||
		!validPort(listener.Endpoint.Port) || (listener.Endpoint.FollowPort && listener.Endpoint.Port != listener.Port) {
		return ListenerV2{}, ErrInvalidConfig
	}
	// A port range is never split by SNI.
	ranged := listener.PortEnd != 0
	bindInput := listener.Address
	if bindInput == "*" {
		bindInput = "0.0.0.0"
	}
	bind, err := normalizeAddress(bindInput, true)
	if err != nil {
		return ListenerV2{}, err
	}
	additional := append([]AdditionalListenerV2(nil), listener.AdditionalListeners...)
	for index := range additional {
		socket := &additional[index]
		ranged = ranged || socket.PortEnd != 0
		if !validUUID(socket.ID) || socket.ID != strings.ToLower(socket.ID) || !validPortRangeV2(socket.Port, socket.PortEnd) ||
			(socket.Protocol != ProtocolTCP && socket.Protocol != ProtocolUDP) ||
			(socket.Protocol == ProtocolUDP && (listener.ProxyProtocolInbound || listener.ProxyProtocolOutbound || listener.TOA)) {
			return ListenerV2{}, ErrInvalidConfig
		}
		if socket.Address == "*" {
			socket.Address = "0.0.0.0"
		}
		address, err := normalizeAddress(socket.Address, true)
		if err != nil {
			return ListenerV2{}, err
		}
		socket.Address = address.String()
	}
	sort.Slice(additional, func(i, j int) bool { return additional[i].ID < additional[j].ID })
	if ranged && listener.TLSPassthrough {
		return ListenerV2{}, ErrInvalidConfig
	}
	endpoint, dns, err := normalizeEndpointV2(listener.Endpoint, listener.DNS)
	if err != nil {
		return ListenerV2{}, err
	}
	if listener.ConnectTimeoutMS < minConnectTimeoutMS || listener.ConnectTimeoutMS > 30_000 ||
		listener.ResponseTimeoutMS < minIdleTimeoutMS || listener.ResponseTimeoutMS > 600_000 ||
		listener.MaxConnectionsPerClient < 1 || listener.MaxConnectionsPerClient > maxClientConnections ||
		listener.DrainTimeoutMS < minDrainTimeoutMS || listener.DrainTimeoutMS > maxDrainTimeoutMS ||
		!validDrainMaxMS(listener.DrainMaxMS) || !validNewConnRate(listener.NewConnRate) ||
		!edgeconfig.ValidL4SubscriptionLimits(listener.SubscriptionLimits) ||
		(listener.Protocol == ProtocolUDP && (listener.ProxyProtocolInbound || listener.ProxyProtocolOutbound)) ||
		(listener.TOA && (listener.Protocol != ProtocolTCP || listener.ProxyProtocolInbound || listener.ProxyProtocolOutbound)) {
		return ListenerV2{}, ErrInvalidConfig
	}
	geo, err := normalizeGeoV2(revision, listener, listener.Geo)
	if err != nil {
		return ListenerV2{}, err
	}
	trustedProxySource := geo.Enabled && len(geo.TrustedProxyCIDRs) != 0
	if listener.ProxyProtocolInbound != trustedProxySource {
		return ListenerV2{}, ErrInvalidConfig
	}
	// The same contract as the control plane (copies, canonical form).
	guardRules, err := edgeconfig.NormalizeL4GuardRules(listener.GuardRules, listener.TLSPassthrough)
	if err != nil {
		return ListenerV2{}, ErrInvalidConfig
	}
	return ListenerV2{
		ID: listener.StreamID, TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID,
		ResourceRevision: resourceRevision,
		Protocol:         listener.Protocol, Address: bind.String(), Port: listener.Port, PortEnd: listener.PortEnd,
		Endpoint: endpoint, DNS: dns, Geo: geo,
		AdditionalListeners: additional,
		ConnectTimeoutMS:    listener.ConnectTimeoutMS, ResponseTimeoutMS: listener.ResponseTimeoutMS,
		MaxConnectionsPerClient: listener.MaxConnectionsPerClient, DrainTimeoutMS: listener.DrainTimeoutMS,
		DrainMaxMS:           cloneDrainMaxMS(listener.DrainMaxMS),
		ProxyProtocolInbound: listener.ProxyProtocolInbound, ProxyProtocolOutbound: listener.ProxyProtocolOutbound,
		ConfigVersionID: listener.ConfigVersionID, ConfigRevision: listener.ConfigRevision,
		TLSPassthrough: listener.TLSPassthrough, ServerNames: serverNames,
		NewConnRate: cloneNewConnRate(listener.NewConnRate), SessionLog: listener.SessionLog,
		GuardRules: guardRules, TOA: listener.TOA, SubscriptionLimits: cloneSubscriptionLimits(listener.SubscriptionLimits),
		ListenIPv6: listener.ListenIPv6, PackageSubscriptionID: listener.PackageSubscriptionID,
	}, nil
}

// validNewConnRate accepts an unset limit or one within the bounds of
// edgeconfig.ValidL4NewConnRate.
func validNewConnRate(value *NewConnRateV2) bool {
	return value == nil || (value.RatePerSecond >= 1 && value.RatePerSecond <= 100_000 &&
		value.Burst >= 0 && value.Burst <= 100_000 && value.BanSeconds >= 0 && value.BanSeconds <= 86_400)
}

func cloneNewConnRate(value *NewConnRateV2) *NewConnRateV2 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// telemetryIdentity is the config version and revision a listener's telemetry
// is attributed to: its own scope's when set, otherwise the runtime set's.
func (listener ListenerV2) telemetryIdentity(config ConfigV2) (string, int64) {
	if listener.ConfigVersionID != "" {
		return listener.ConfigVersionID, listener.ConfigRevision
	}
	return config.VersionID, config.Revision
}

func listenerSocketsV2(listener ListenerV2) []AdditionalListenerV2 {
	sockets := make([]AdditionalListenerV2, 1, 1+len(listener.AdditionalListeners))
	sockets[0] = AdditionalListenerV2{ID: listener.ID, Protocol: listener.Protocol, Address: listener.Address, Port: listener.Port,
		PortEnd: listener.PortEnd}
	return append(sockets, listener.AdditionalListeners...)
}

// onSocket is listener as served on one of its sockets (ID, bind, ports).
func (listener ListenerV2) onSocket(socket AdditionalListenerV2) ListenerV2 {
	listener.ID, listener.Protocol, listener.Address = socket.ID, socket.Protocol, socket.Address
	listener.Port, listener.PortEnd = socket.Port, socket.PortEnd
	return listener
}

// lastPort is the last port of the socket's range (Port when single).
func (listener ListenerV2) lastPort() int {
	if listener.PortEnd != 0 {
		return listener.PortEnd
	}
	return listener.Port
}

// validPortRangeV2 checks port..portEnd as edgeconfig.ValidL4PortRange.
func validPortRangeV2(port, portEnd int) bool {
	_, ok := edgeconfig.ValidL4PortRange(port, portEnd)
	return ok
}

func normalizeEndpointV2(endpoint EndpointV2, policy DNSPolicyV2) (EndpointV2, DNSPolicyV2, error) {
	if (endpoint.Address == "") == (endpoint.Host == "") {
		return EndpointV2{}, DNSPolicyV2{}, ErrInvalidConfig
	}
	if endpoint.Balance != "" && endpoint.Balance != edgeconfig.L4BalanceIPHash {
		return EndpointV2{}, DNSPolicyV2{}, ErrInvalidConfig
	}
	if endpoint.Address != "" {
		if policy != (DNSPolicyV2{}) {
			return EndpointV2{}, DNSPolicyV2{}, ErrInvalidConfig
		}
		address, parseErr := normalizeAddress(endpoint.Address, false)
		if parseErr != nil {
			return EndpointV2{}, DNSPolicyV2{}, ErrInvalidConfig
		}
		normalized := EndpointV2{Address: address.String(), Port: endpoint.Port, FollowPort: endpoint.FollowPort, Balance: endpoint.Balance}
		if len(endpoint.Origins) != 0 {
			// The same contract as the control plane.
			origins, err := edgeconfig.NormalizeL4Origins(endpoint.Origins)
			if err != nil || endpoint.FollowPort || origins[0].Address != normalized.Address {
				return EndpointV2{}, DNSPolicyV2{}, ErrInvalidConfig
			}
			normalized.Origins = origins
		}
		return normalized, DNSPolicyV2{}, nil
	}
	if len(endpoint.Origins) != 0 {
		return EndpointV2{}, DNSPolicyV2{}, ErrInvalidConfig
	}
	normalizedPolicy, err := normalizeDNSPolicyV2(policy)
	if err != nil {
		return EndpointV2{}, DNSPolicyV2{}, err
	}
	host, err := canonicalDNSHost(endpoint.Host)
	if err != nil {
		return EndpointV2{}, DNSPolicyV2{}, err
	}
	return EndpointV2{Host: host, Port: endpoint.Port, FollowPort: endpoint.FollowPort, Balance: endpoint.Balance}, normalizedPolicy, nil
}

func normalizeDNSPolicyV2(policy DNSPolicyV2) (DNSPolicyV2, error) {
	if policy.PositiveMinTTLSeconds < 1 || policy.PositiveMinTTLSeconds > 3_600 ||
		policy.PositiveMaxTTLSeconds < policy.PositiveMinTTLSeconds || policy.PositiveMaxTTLSeconds > 86_400 ||
		policy.NegativeTTLSeconds < 1 || policy.NegativeTTLSeconds > 3_600 ||
		policy.StaleIfErrorSeconds < policy.PositiveMaxTTLSeconds || policy.StaleIfErrorSeconds > 86_400 || policy.AllowPrivateAddresses {
		return DNSPolicyV2{}, ErrInvalidConfig
	}
	return policy, nil
}

func canonicalDNSHost(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", ErrInvalidConfig
	}
	value = strings.TrimSuffix(value, ".")
	ascii, err := idna.Lookup.ToASCII(value)
	ascii = strings.ToLower(ascii)
	if err != nil || len(ascii) == 0 || len(ascii) > 253 || ascii == "localhost" || strings.HasSuffix(ascii, ".localhost") ||
		strings.HasSuffix(ascii, ".in-addr.arpa") || strings.HasSuffix(ascii, ".ip6.arpa") {
		return "", ErrInvalidConfig
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", ErrInvalidConfig
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrInvalidConfig
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidConfig
		}
	}
	return ascii, nil
}

func normalizeGeoV2(revision int64, listener ListenerV2, geo GeoPolicyV2) (GeoPolicyV2, error) {
	if !geo.Enabled {
		if (geo.UnknownRegionAction != "" && geo.UnknownRegionAction != GeoActionAllow) || len(geo.TrustedProxyCIDRs) != 0 || len(geo.BlockedRegions) != 0 || len(geo.RegionCIDRs) != 0 {
			return GeoPolicyV2{}, ErrInvalidConfig
		}
		return GeoPolicyV2{TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID, Revision: revision,
			UnknownRegionAction: GeoActionAllow, TrustedProxyCIDRs: []string{}, BlockedRegions: []string{}, RegionCIDRs: []RegionCIDRsV2{}}, nil
	}
	if geo.TenantID != listener.TenantID || geo.SiteID != listener.SiteID || geo.StreamID != listener.StreamID || geo.Revision != revision ||
		(geo.UnknownRegionAction != GeoActionAllow && geo.UnknownRegionAction != GeoActionBlock) {
		return GeoPolicyV2{}, ErrInvalidConfig
	}
	trusted, err := normalizeGeoCIDRs(geo.TrustedProxyCIDRs, true)
	if err != nil {
		return GeoPolicyV2{}, err
	}
	blocked, err := normalizeRegions(geo.BlockedRegions)
	if err != nil {
		return GeoPolicyV2{}, err
	}
	regionCIDRs := make([]RegionCIDRsV2, 0, len(geo.RegionCIDRs))
	regionAuthority := make(map[string]struct{}, len(geo.RegionCIDRs))
	var allPrefixes []netip.Prefix
	for _, mapping := range geo.RegionCIDRs {
		region := strings.ToLower(strings.TrimSpace(mapping.Region))
		if !geoRegionPattern.MatchString(region) {
			return GeoPolicyV2{}, ErrInvalidConfig
		}
		if _, duplicate := regionAuthority[region]; duplicate {
			return GeoPolicyV2{}, ErrInvalidConfig
		}
		cidrs, normalizeErr := normalizeGeoCIDRs(mapping.CIDRs, false)
		if normalizeErr != nil || len(cidrs) == 0 {
			return GeoPolicyV2{}, ErrInvalidConfig
		}
		for _, raw := range cidrs {
			prefix := netip.MustParsePrefix(raw)
			for _, prior := range allPrefixes {
				if prior.Addr().BitLen() == prefix.Addr().BitLen() && (prior.Contains(prefix.Addr()) || prefix.Contains(prior.Addr())) {
					return GeoPolicyV2{}, ErrInvalidConfig
				}
			}
			allPrefixes = append(allPrefixes, prefix)
		}
		regionAuthority[region] = struct{}{}
		regionCIDRs = append(regionCIDRs, RegionCIDRsV2{Region: region, CIDRs: cidrs})
	}
	for _, region := range blocked {
		if _, exists := regionAuthority[region]; !exists {
			return GeoPolicyV2{}, ErrInvalidConfig
		}
	}
	sort.Slice(regionCIDRs, func(i, j int) bool { return regionCIDRs[i].Region < regionCIDRs[j].Region })
	return GeoPolicyV2{
		Enabled: true, TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID, Revision: revision,
		UnknownRegionAction: geo.UnknownRegionAction, TrustedProxyCIDRs: trusted, BlockedRegions: blocked, RegionCIDRs: regionCIDRs,
	}, nil
}

func normalizeRegions(values []string) ([]string, error) {
	normalized := make([]string, len(values))
	seen := make(map[string]struct{}, len(normalized))
	for index, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if !geoRegionPattern.MatchString(value) {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[value] = struct{}{}
		normalized[index] = value
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeGeoCIDRs(values []string, rejectUnspecified bool) ([]string, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() || (rejectUnspecified && prefix.Addr().IsUnspecified()) {
			return nil, ErrInvalidConfig
		}
		prefix = prefix.Masked()
		if _, duplicate := seen[prefix]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr().BitLen() != prefixes[j].Addr().BitLen() {
			return prefixes[i].Addr().BitLen() < prefixes[j].Addr().BitLen()
		}
		if comparison := prefixes[i].Addr().Compare(prefixes[j].Addr()); comparison != 0 {
			return comparison < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	normalized := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		normalized[index] = prefix.String()
	}
	return normalized, nil
}

func safeResolvedAddress(address netip.Addr, allowPrivate bool) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsLoopback() ||
		address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return false
	}
	for _, prefix := range alwaysForbiddenAddressPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return allowPrivate || !address.IsPrivate()
}

func addressClass(address netip.Addr) string {
	if address.IsPrivate() {
		return "private"
	}
	return "public"
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == strings.ToLower(value)
}

func listenerV2BindsOverlap(left, right ListenerV2) bool {
	if left.Protocol != right.Protocol || left.Port > right.lastPort() || right.Port > left.lastPort() {
		return false
	}
	leftAddress, rightAddress := netip.MustParseAddr(left.Address), netip.MustParseAddr(right.Address)
	if leftAddress.BitLen() != rightAddress.BitLen() {
		return false
	}
	return leftAddress == rightAddress || leftAddress.IsUnspecified() || rightAddress.IsUnspecified()
}

func configV2Digest(config ConfigV2) (string, error) {
	canonical, err := CanonicalV2(config)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func cloneSubscriptionLimits(value *SubscriptionLimitsV2) *SubscriptionLimitsV2 {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
