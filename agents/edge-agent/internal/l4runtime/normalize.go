package l4runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"time"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func normalize(config Config) (Config, string, []byte, error) {
	if config.SchemaVersion != SchemaVersionV1 || !identifierPattern.MatchString(config.VersionID) ||
		(config.DrainTimeoutMS != 0 && (config.DrainTimeoutMS < minDrainTimeoutMS || config.DrainTimeoutMS > maxDrainTimeoutMS)) ||
		!validDrainMaxMS(config.DrainMaxMS) {
		return Config{}, "", nil, ErrInvalidConfig
	}
	if len(config.Listeners) > maxListeners || len(config.UpstreamPools) > maxPools ||
		(len(config.Listeners) == 0) != (len(config.UpstreamPools) == 0) {
		return Config{}, "", nil, ErrInvalidConfig
	}

	normalized := Config{
		SchemaVersion:  config.SchemaVersion,
		VersionID:      config.VersionID,
		DrainTimeoutMS: config.DrainTimeoutMS,
		DrainMaxMS:     cloneDrainMaxMS(config.DrainMaxMS),
		Listeners:      make([]Listener, 0, len(config.Listeners)),
		UpstreamPools:  make([]UpstreamPool, 0, len(config.UpstreamPools)),
	}
	pools := make(map[string]struct{}, len(config.UpstreamPools))
	for _, pool := range config.UpstreamPools {
		if !identifierPattern.MatchString(pool.ID) || len(pool.Endpoints) == 0 || len(pool.Endpoints) > maxEndpointsPerPool {
			return Config{}, "", nil, ErrInvalidConfig
		}
		if _, exists := pools[pool.ID]; exists {
			return Config{}, "", nil, ErrInvalidConfig
		}
		pools[pool.ID] = struct{}{}
		normalizedPool := UpstreamPool{ID: pool.ID, Endpoints: make([]Endpoint, 0, len(pool.Endpoints))}
		seenEndpoints := make(map[string]struct{}, len(pool.Endpoints))
		explicitOrder := false
		for _, endpoint := range pool.Endpoints {
			explicitOrder = explicitOrder || endpoint.Priority != 0 || endpoint.Backup
		}
		priorities := make(map[int]struct{}, len(pool.Endpoints))
		for _, endpoint := range pool.Endpoints {
			address, err := normalizeAddress(endpoint.Address, false)
			if err != nil || !validPort(endpoint.Port) || endpoint.Weight < 1 || endpoint.Weight > maxWeight ||
				endpoint.MaxFails < 1 || endpoint.MaxFails > maxFails ||
				endpoint.FailTimeoutMS < minFailTimeoutMS || endpoint.FailTimeoutMS > maxFailTimeoutMS || endpoint.FailTimeoutMS%1_000 != 0 {
				return Config{}, "", nil, ErrInvalidConfig
			}
			if explicitOrder {
				if endpoint.Priority < 1 || endpoint.Priority > len(pool.Endpoints) {
					return Config{}, "", nil, ErrInvalidConfig
				}
				if _, duplicate := priorities[endpoint.Priority]; duplicate {
					return Config{}, "", nil, ErrInvalidConfig
				}
				priorities[endpoint.Priority] = struct{}{}
			}
			key := address.String() + "\x00" + strconv.Itoa(endpoint.Port)
			if _, exists := seenEndpoints[key]; exists {
				return Config{}, "", nil, ErrInvalidConfig
			}
			seenEndpoints[key] = struct{}{}
			normalizedPool.Endpoints = append(normalizedPool.Endpoints, Endpoint{
				Address: address.String(), Port: endpoint.Port, Weight: endpoint.Weight,
				MaxFails: endpoint.MaxFails, FailTimeoutMS: endpoint.FailTimeoutMS,
				Priority: endpoint.Priority, Backup: endpoint.Backup,
			})
		}
		sort.Slice(normalizedPool.Endpoints, func(i, j int) bool {
			left, right := normalizedPool.Endpoints[i], normalizedPool.Endpoints[j]
			if explicitOrder && left.Priority != right.Priority {
				return left.Priority < right.Priority
			}
			if left.Address != right.Address {
				return netip.MustParseAddr(left.Address).Compare(netip.MustParseAddr(right.Address)) < 0
			}
			if left.Port != right.Port {
				return left.Port < right.Port
			}
			if left.Weight != right.Weight {
				return left.Weight < right.Weight
			}
			if left.MaxFails != right.MaxFails {
				return left.MaxFails < right.MaxFails
			}
			return left.FailTimeoutMS < right.FailTimeoutMS
		})
		if explicitOrder {
			backupSeen, primarySeen := false, false
			for index, endpoint := range normalizedPool.Endpoints {
				if endpoint.Priority != index+1 || backupSeen && !endpoint.Backup {
					return Config{}, "", nil, ErrInvalidConfig
				}
				backupSeen = backupSeen || endpoint.Backup
				primarySeen = primarySeen || !endpoint.Backup
			}
			if !primarySeen {
				return Config{}, "", nil, ErrInvalidConfig
			}
		}
		normalized.UpstreamPools = append(normalized.UpstreamPools, normalizedPool)
	}
	sort.Slice(normalized.UpstreamPools, func(i, j int) bool {
		return normalized.UpstreamPools[i].ID < normalized.UpstreamPools[j].ID
	})

	listenerIDs := make(map[string]struct{}, len(config.Listeners))
	for _, listener := range config.Listeners {
		if !identifierPattern.MatchString(listener.ID) || (listener.Protocol != ProtocolTCP && listener.Protocol != ProtocolUDP) {
			return Config{}, "", nil, ErrInvalidConfig
		}
		if _, exists := listenerIDs[listener.ID]; exists {
			return Config{}, "", nil, ErrInvalidConfig
		}
		listenerIDs[listener.ID] = struct{}{}
		address, err := normalizeAddress(listener.Address, true)
		if err != nil || !validPort(listener.Port) {
			return Config{}, "", nil, ErrInvalidConfig
		}
		if _, exists := pools[listener.UpstreamPoolID]; !exists ||
			listener.ConnectTimeoutMS < minConnectTimeoutMS || listener.ConnectTimeoutMS > maxConnectTimeoutMS ||
			listener.IdleTimeoutMS < minIdleTimeoutMS || listener.IdleTimeoutMS > maxIdleTimeoutMS ||
			listener.MaxConnectionsPerClient < 1 || listener.MaxConnectionsPerClient > maxClientConnections ||
			listener.ProxyProtocolOutbound != listener.ProxyProtocolV1 {
			return Config{}, "", nil, ErrInvalidConfig
		}
		if listener.Protocol == ProtocolUDP && (listener.ProxyProtocolInbound || listener.ProxyProtocolV1) {
			return Config{}, "", nil, ErrUnsupported
		}
		trustedProxyCIDRs, err := normalizeTrustedProxyCIDRs(listener.Protocol, listener.ProxyProtocolInbound, listener.TrustedProxyCIDRs)
		if err != nil {
			return Config{}, "", nil, err
		}
		trafficHealth, err := normalizeTrafficHealth(listener.Protocol, listener.TrafficHealth)
		if err != nil {
			return Config{}, "", nil, err
		}
		normalized.Listeners = append(normalized.Listeners, Listener{
			ID: listener.ID, Disabled: listener.Disabled, Protocol: listener.Protocol, Address: address.String(), Port: listener.Port,
			UpstreamPoolID: listener.UpstreamPoolID, ConnectTimeoutMS: listener.ConnectTimeoutMS,
			IdleTimeoutMS: listener.IdleTimeoutMS, ProxyProtocolInbound: listener.ProxyProtocolInbound,
			ProxyProtocolOutbound:   listener.ProxyProtocolOutbound,
			ProxyProtocolV1:         listener.ProxyProtocolV1,
			TrustedProxyCIDRs:       trustedProxyCIDRs,
			MaxConnectionsPerClient: listener.MaxConnectionsPerClient,
			TrafficHealth:           trafficHealth,
		})
	}
	sort.Slice(normalized.Listeners, func(i, j int) bool {
		left, right := normalized.Listeners[i], normalized.Listeners[j]
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		leftAddress, rightAddress := netip.MustParseAddr(left.Address), netip.MustParseAddr(right.Address)
		if comparison := leftAddress.Compare(rightAddress); comparison != 0 {
			return comparison < 0
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		return left.ID < right.ID
	})
	for leftIndex := 0; leftIndex < len(normalized.Listeners); leftIndex++ {
		for rightIndex := leftIndex + 1; rightIndex < len(normalized.Listeners); rightIndex++ {
			if bindsOverlap(normalized.Listeners[leftIndex], normalized.Listeners[rightIndex]) {
				return Config{}, "", nil, ErrInvalidConfig
			}
		}
	}

	canonical, err := json.Marshal(normalized)
	if err != nil {
		return Config{}, "", nil, ErrInvalidConfig
	}
	digest := sha256.Sum256(canonical)
	return normalized, hex.EncodeToString(digest[:]), append(canonical, '\n'), nil
}

func normalizeTrustedProxyCIDRs(protocol Protocol, enabled bool, values []string) ([]string, error) {
	if !enabled {
		if len(values) != 0 {
			return nil, ErrInvalidConfig
		}
		return nil, nil
	}
	if protocol != ProtocolTCP || len(values) == 0 || len(values) > maxTrustedProxyCIDRs {
		return nil, ErrInvalidConfig
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		prefix = prefix.Masked()
		address := prefix.Addr()
		if address.Is4In6() || address.IsMulticast() || address.IsUnspecified() || prefix.Bits() == 0 {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		left, right := prefixes[i], prefixes[j]
		if left.Addr().BitLen() != right.Addr().BitLen() {
			return left.Addr().BitLen() < right.Addr().BitLen()
		}
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison < 0
		}
		return left.Bits() < right.Bits()
	})
	for index, prefix := range prefixes {
		for previous := 0; previous < index; previous++ {
			if prefixes[previous].Contains(prefix.Addr()) {
				return nil, ErrInvalidConfig
			}
		}
	}
	normalized := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		normalized[index] = prefix.String()
	}
	return normalized, nil
}

func normalizeTrafficHealth(protocol Protocol, policy *TrafficHealthPolicy) (*TrafficHealthPolicy, error) {
	if policy == nil {
		return nil, nil
	}
	requestPresent := len(policy.Request) > 0
	responsePresent := len(policy.ExpectedResponse) > 0
	if policy.TimeoutMS < minTrafficHealthMS || policy.TimeoutMS > maxTrafficHealthMS ||
		policy.Attempts < 1 || policy.Attempts > maxTrafficAttempts ||
		len(policy.Request) > maxTrafficHealthBytes || len(policy.ExpectedResponse) > maxTrafficHealthBytes ||
		requestPresent != responsePresent || protocol == ProtocolUDP && !requestPresent {
		return nil, ErrInvalidConfig
	}
	return &TrafficHealthPolicy{
		Request:          append([]byte(nil), policy.Request...),
		ExpectedResponse: append([]byte(nil), policy.ExpectedResponse...),
		TimeoutMS:        policy.TimeoutMS,
		Attempts:         policy.Attempts,
	}, nil
}

func normalizeAddress(value string, allowUnspecified bool) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsMulticast() || (!allowUnspecified && address.IsUnspecified()) {
		return netip.Addr{}, ErrInvalidConfig
	}
	return address, nil
}

func bindsOverlap(left, right Listener) bool {
	if left.Disabled || right.Disabled || left.Protocol != right.Protocol ||
		left.Port > right.lastPort() || right.Port > left.lastPort() {
		return false
	}
	leftAddress, rightAddress := netip.MustParseAddr(left.Address), netip.MustParseAddr(right.Address)
	if leftAddress.BitLen() != rightAddress.BitLen() {
		return false
	}
	return leftAddress == rightAddress || leftAddress.IsUnspecified() || rightAddress.IsUnspecified()
}

// lastPort is the last port of the listener's range (Port when single).
func (listener Listener) lastPort() int {
	if listener.PortEnd != 0 {
		return listener.PortEnd
	}
	return listener.Port
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}

// validDrainMaxMS accepts an unset limit, 0 (unlimited), or 1 s .. 7 days.
func validDrainMaxMS(value *int) bool {
	return value == nil || *value == 0 || (*value >= 1_000 && *value <= maxDrainMaxMS)
}

func cloneDrainMaxMS(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

// mergeDrainMaxMS combines the limits of streams sharing one runtime: unset
// means the default, 0 (unlimited) wins, otherwise the longest applies.
func mergeDrainMaxMS(current, next *int) *int {
	switch {
	case next == nil:
		return current
	case current == nil || *next == 0:
		return cloneDrainMaxMS(next)
	case *current == 0:
		return current
	default:
		merged := max(*current, *next)
		return &merged
	}
}

// drainLimit is the duration a configuration's drain_max_ms names.
func drainLimit(value *int) time.Duration {
	if value == nil {
		return time.Duration(DefaultDrainMaxMS) * time.Millisecond
	}
	return time.Duration(*value) * time.Millisecond
}
