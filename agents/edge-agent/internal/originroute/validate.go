package originroute

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const maxPolicyBytes = 1 << 20

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func Parse(raw []byte) (Policy, error) {
	if len(raw) == 0 || len(raw) > maxPolicyBytes {
		return Policy{}, invalid("policy size must be between 1 and %d bytes", maxPolicyBytes)
	}
	if err := rejectDuplicateJSONKeys(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return Policy{}, invalid("decode policy: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, invalid("decode policy: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Policy{}, invalid("policy must contain exactly one JSON value")
	}
	return Normalize(policy)
}

func rejectDuplicateJSONKeys(decoder *json.Decoder) error {
	var decodeValue func() error
	decodeValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, exists := keys[key]; exists {
					return fmt.Errorf("duplicate object key %q", key)
				}
				keys[key] = struct{}{}
				if err := decodeValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return fmt.Errorf("object is not terminated")
			}
		case '[':
			for decoder.More() {
				if err := decodeValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return fmt.Errorf("array is not terminated")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
		return nil
	}
	return decodeValue()
}

func Normalize(policy Policy) (Policy, error) {
	if policy.Schema != SchemaV1 || policy.Revision == 0 || policy.Revision > MaxRevision ||
		!tokenPattern.MatchString(policy.VersionID) {
		return Policy{}, invalid("schema, positive revision, and version_id are required")
	}
	algorithmPolicy, err := edgeconfig.NormalizeOriginRouteAlgorithmPolicy(originRouteAlgorithmPolicy(policy))
	if err != nil {
		return Policy{}, invalid("algorithm contract: %v", err)
	}
	algorithms := make(map[string]Algorithm, len(algorithmPolicy.Pools))
	for _, pool := range algorithmPolicy.Pools {
		algorithms[pool.PoolID] = pool.Algorithm
	}
	node, err := normalizeNode(policy.Node)
	if err != nil {
		return Policy{}, err
	}
	listeners, err := normalizeListeners(policy.Listeners)
	if err != nil {
		return Policy{}, err
	}
	pools, poolIndex, err := normalizePools(policy.Pools, node, algorithms)
	if err != nil {
		return Policy{}, err
	}
	defaultPool, ok := poolIndex[policy.DefaultPoolID]
	if !ok {
		return Policy{}, invalid("default_pool_id does not exist")
	}
	defaultFallback, err := normalizeFallback(defaultPool, policy.DefaultFallbackPoolID, poolIndex, node)
	if err != nil {
		return Policy{}, invalid("default fallback: %v", err)
	}
	routes, err := normalizeRoutes(policy.Routes, poolIndex, node)
	if err != nil {
		return Policy{}, err
	}
	retry, err := normalizeRetry(policy.Retry)
	if err != nil {
		return Policy{}, err
	}
	l2, err := normalizeL2(policy.L2)
	if err != nil {
		return Policy{}, err
	}
	adaptive, err := normalizeAdaptive(policy.Adaptive)
	if err != nil {
		return Policy{}, err
	}
	dns, err := normalizeDNSPolicy(policy.DNS, pools)
	if err != nil {
		return Policy{}, err
	}
	if err := validateIngressFamilies(listeners, pools); err != nil {
		return Policy{}, err
	}
	return Policy{
		Schema: SchemaV1, Revision: policy.Revision, TenantID: algorithmPolicy.TenantID,
		SiteID: algorithmPolicy.SiteID, VersionID: algorithmPolicy.VersionID, Node: node,
		Listeners: listeners, Pools: pools, DefaultPoolID: defaultPool.ID,
		DefaultFallbackPoolID: defaultFallback, Routes: routes, Retry: retry, L2: l2,
		Adaptive: adaptive, DNS: dns,
	}, nil
}

func originRouteAlgorithmPolicy(policy Policy) edgeconfig.OriginRouteAlgorithmPolicy {
	pools := make([]edgeconfig.OriginRoutePoolAlgorithm, len(policy.Pools))
	for index, pool := range policy.Pools {
		pools[index] = edgeconfig.OriginRoutePoolAlgorithm{PoolID: pool.ID, Algorithm: pool.Algorithm}
	}
	return edgeconfig.OriginRouteAlgorithmPolicy{
		TenantID: policy.TenantID, SiteID: policy.SiteID, VersionID: policy.VersionID, Pools: pools,
	}
}

func normalizeNode(node Node) (Node, error) {
	if !tokenPattern.MatchString(node.ID) || !validRegion(node.Region) ||
		(node.Tier != TierL1 && node.Tier != TierL2) {
		return Node{}, invalid("node id, region, or tier is invalid")
	}
	return Node{ID: node.ID, Region: strings.ToLower(node.Region), Tier: node.Tier}, nil
}

func normalizeListeners(input []Listener) ([]Listener, error) {
	if len(input) == 0 || len(input) > MaxListeners {
		return nil, invalid("listener count must be between 1 and %d", MaxListeners)
	}
	result := make([]Listener, len(input))
	seenIDs := make(map[string]struct{}, len(input))
	seenSockets := make(map[string]struct{}, len(input))
	for index, listener := range input {
		if !tokenPattern.MatchString(listener.ID) || listener.Port == 0 {
			return nil, invalid("listener %d id or port is invalid", index)
		}
		address, err := parseSafeAddress(listener.Address, true)
		if err != nil {
			return nil, invalid("listener %d address: %v", index, err)
		}
		ipv4, err := parseOptionalSource(listener.IngressSourceIPv4, true)
		if err != nil {
			return nil, invalid("listener %d ingress IPv4: %v", index, err)
		}
		ipv6, err := parseOptionalSource(listener.IngressSourceIPv6, false)
		if err != nil {
			return nil, invalid("listener %d ingress IPv6: %v", index, err)
		}
		socket := netip.AddrPortFrom(address, listener.Port).String()
		if _, exists := seenIDs[listener.ID]; exists {
			return nil, invalid("duplicate listener id %q", listener.ID)
		}
		if _, exists := seenSockets[socket]; exists {
			return nil, invalid("duplicate listener socket %q", socket)
		}
		seenIDs[listener.ID], seenSockets[socket] = struct{}{}, struct{}{}
		result[index] = Listener{
			ID: listener.ID, Address: address.String(), Port: listener.Port,
			IngressSourceIPv4: ipv4, IngressSourceIPv6: ipv6,
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func normalizePools(input []Pool, node Node, algorithms map[string]Algorithm) ([]Pool, map[string]Pool, error) {
	if len(input) == 0 || len(input) > MaxPools {
		return nil, nil, invalid("pool count must be between 1 and %d", MaxPools)
	}
	result := make([]Pool, len(input))
	index := make(map[string]Pool, len(input))
	for poolIndex, pool := range input {
		if !tokenPattern.MatchString(pool.ID) || (pool.Kind != PoolOrigin && pool.Kind != PoolL2) ||
			len(pool.Endpoints) == 0 || len(pool.Endpoints) > MaxEndpointsPerPool {
			return nil, nil, invalid("pool %d identity, kind, or endpoint count is invalid", poolIndex)
		}
		if node.Tier == TierL2 && pool.Kind == PoolL2 {
			return nil, nil, invalid("L2 node policy cannot route to another L2")
		}
		if _, exists := index[pool.ID]; exists {
			return nil, nil, invalid("duplicate pool id %q", pool.ID)
		}
		endpoints := make([]Endpoint, len(pool.Endpoints))
		seen := make(map[string]struct{}, len(pool.Endpoints))
		for endpointIndex, endpoint := range pool.Endpoints {
			value, err := normalizeEndpoint(endpoint, pool.Kind, node.ID)
			if err != nil {
				return nil, nil, invalid("pool %q endpoint %d: %v", pool.ID, endpointIndex, err)
			}
			key := strings.ToLower(value.Host) + fmt.Sprintf(":%d", value.Port)
			if _, exists := seen[value.ID]; exists {
				return nil, nil, invalid("pool %q has duplicate endpoint id %q", pool.ID, value.ID)
			}
			if _, exists := seen[key]; exists {
				return nil, nil, invalid("pool %q has duplicate endpoint %q", pool.ID, key)
			}
			seen[value.ID], seen[key] = struct{}{}, struct{}{}
			endpoints[endpointIndex] = value
		}
		sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
		value := Pool{ID: pool.ID, Kind: pool.Kind, Algorithm: algorithms[pool.ID], Endpoints: endpoints}
		result[poolIndex], index[pool.ID] = value, value
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, index, nil
}

func normalizeEndpoint(endpoint Endpoint, kind PoolKind, localNodeID string) (Endpoint, error) {
	if !tokenPattern.MatchString(endpoint.ID) || endpoint.Port == 0 || endpoint.Weight < 1 || endpoint.Weight > 100 {
		return Endpoint{}, fmt.Errorf("id, port, or weight is invalid")
	}
	host, err := normalizeHost(endpoint.Host, kind == PoolOrigin)
	if err != nil {
		return Endpoint{}, err
	}
	if kind == PoolL2 {
		if !tokenPattern.MatchString(endpoint.NodeID) || endpoint.NodeID == localNodeID {
			return Endpoint{}, fmt.Errorf("L2 endpoint must name a different node")
		}
	} else if endpoint.NodeID != "" {
		return Endpoint{}, fmt.Errorf("origin endpoint must not name a node")
	}
	return Endpoint{
		ID: endpoint.ID, Host: host, Port: endpoint.Port,
		NodeID: endpoint.NodeID, Weight: endpoint.Weight,
	}, nil
}

func normalizeRoutes(input []Route, pools map[string]Pool, node Node) ([]Route, error) {
	if len(input) > MaxRoutes {
		return nil, invalid("route count must not exceed %d", MaxRoutes)
	}
	result := make([]Route, len(input))
	seenIDs := make(map[string]struct{}, len(input))
	seenConditions := make(map[string]string, len(input))
	for index, route := range input {
		if !tokenPattern.MatchString(route.ID) || route.Priority < -1000 || route.Priority > 1000 {
			return nil, invalid("route %d id or priority is invalid", index)
		}
		if _, exists := seenIDs[route.ID]; exists {
			return nil, invalid("duplicate route id %q", route.ID)
		}
		seenIDs[route.ID] = struct{}{}
		path, err := normalizePathPrefix(route.PathPrefix)
		if err != nil {
			return nil, invalid("route %q path: %v", route.ID, err)
		}
		regions, err := normalizeRegions(route.NodeRegions)
		if err != nil {
			return nil, invalid("route %q regions: %v", route.ID, err)
		}
		cidrs, err := normalizeCIDRs(route.ClientCIDRs)
		if err != nil {
			return nil, invalid("route %q client CIDRs: %v", route.ID, err)
		}
		hosts, err := normalizeRouteHosts(route.Hosts)
		if err != nil {
			return nil, invalid("route %q hosts: %v", route.ID, err)
		}
		if path == "" && len(regions) == 0 && len(cidrs) == 0 && len(hosts) == 0 {
			return nil, invalid("route %q must have at least one condition", route.ID)
		}
		pool, exists := pools[route.PoolID]
		if !exists {
			return nil, invalid("route %q pool does not exist", route.ID)
		}
		fallback, err := normalizeFallback(pool, route.FallbackPoolID, pools, node)
		if err != nil {
			return nil, invalid("route %q fallback: %v", route.ID, err)
		}
		value := Route{
			ID: route.ID, Priority: route.Priority, PathPrefix: path, NodeRegions: regions,
			ClientCIDRs: cidrs, Hosts: hosts, PoolID: pool.ID, FallbackPoolID: fallback,
		}
		conditionKey := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", value.Priority, value.PathPrefix,
			strings.Join(value.NodeRegions, ","), strings.Join(value.ClientCIDRs, ","), strings.Join(value.Hosts, ","))
		if previous, exists := seenConditions[conditionKey]; exists {
			return nil, fmt.Errorf("%w: routes %q and %q have identical rank and conditions", ErrConflict, previous, value.ID)
		}
		seenConditions[conditionKey] = value.ID
		result[index] = value
	}
	sort.Slice(result, func(i, j int) bool { return routeLess(result[i], result[j]) })
	return result, nil
}

func normalizeFallback(pool Pool, fallbackID string, pools map[string]Pool, node Node) (string, error) {
	if pool.Kind == PoolOrigin {
		if fallbackID != "" {
			return "", fmt.Errorf("origin pool must not have a fallback")
		}
		return "", nil
	}
	if node.Tier != TierL1 || fallbackID == "" {
		return "", fmt.Errorf("L2 pool on L1 requires a direct-origin fallback")
	}
	fallback, exists := pools[fallbackID]
	if !exists || fallback.Kind != PoolOrigin || fallback.ID == pool.ID {
		return "", fmt.Errorf("fallback must name a distinct origin pool")
	}
	return fallback.ID, nil
}

func normalizeRetry(value RetryPolicy) (RetryPolicy, error) {
	if value.MaxAttempts < 1 || value.MaxAttempts > MaxAttempts ||
		value.ConnectTimeoutMS < 10 || value.ConnectTimeoutMS > 60000 ||
		value.ReadTimeoutMS < 10 || value.ReadTimeoutMS > 60000 ||
		value.TotalBudgetMS < value.ConnectTimeoutMS+value.ReadTimeoutMS || value.TotalBudgetMS > 120000 {
		return RetryPolicy{}, invalid("retry attempts or timeout budget is invalid")
	}
	if len(value.Methods) == 0 || len(value.Methods) > 2 {
		return RetryPolicy{}, invalid("retry methods must explicitly contain GET and/or HEAD")
	}
	methods := make([]string, len(value.Methods))
	seen := make(map[string]struct{}, len(value.Methods))
	for index, method := range value.Methods {
		method = strings.ToUpper(method)
		if method != "GET" && method != "HEAD" {
			return RetryPolicy{}, invalid("retry method %q is not replay-safe", method)
		}
		if _, exists := seen[method]; exists {
			return RetryPolicy{}, invalid("duplicate retry method %q", method)
		}
		seen[method], methods[index] = struct{}{}, method
	}
	sort.Strings(methods)
	return RetryPolicy{
		Methods: methods, MaxAttempts: value.MaxAttempts, ConnectTimeoutMS: value.ConnectTimeoutMS,
		ReadTimeoutMS: value.ReadTimeoutMS, TotalBudgetMS: value.TotalBudgetMS,
	}, nil
}

func normalizeL2(value L2Policy) (L2Policy, error) {
	if value.FailureThreshold < 1 || value.FailureThreshold > 10 ||
		value.RecoveryThreshold < 1 || value.RecoveryThreshold > 10 ||
		value.ProbeIntervalMS < 100 || value.ProbeIntervalMS > 60000 ||
		value.MaxHops < 1 || value.MaxHops > 8 {
		return L2Policy{}, invalid("L2 failure, recovery, probe, or hop bounds are invalid")
	}
	return value, nil
}

func normalizeAdaptive(value *AdaptivePolicy) (*AdaptivePolicy, error) {
	if value == nil {
		return nil, nil
	}
	if value.Version != 1 ||
		(value.Mode != AdaptiveOff && value.Mode != AdaptiveShadow && value.Mode != AdaptiveActive) {
		return nil, invalid("adaptive version or mode is invalid")
	}
	if value.Mode == AdaptiveOff {
		return nil, nil
	}
	if value.MinimumSamples < 2 || value.MinimumSamples > 1000 ||
		value.SampleFreshnessMS < 100 || value.SampleFreshnessMS > 300000 ||
		value.PeakEWMAHalfLifeMS < 100 || value.PeakEWMAHalfLifeMS > 60000 ||
		value.ExplorationPercent < 1 || value.ExplorationPercent > 10 {
		return nil, invalid("adaptive sample, EWMA, or exploration bounds are invalid")
	}
	if value.SlowStart.InitialWeightPercent < 1 || value.SlowStart.InitialWeightPercent > 100 ||
		value.SlowStart.RampMS < 100 || value.SlowStart.RampMS > 300000 ||
		value.SlowStart.HardTimeoutMS < value.SlowStart.RampMS || value.SlowStart.HardTimeoutMS > 600000 {
		return nil, invalid("adaptive slow-start bounds are invalid")
	}
	if value.Outlier.MinimumSamples < value.MinimumSamples || value.Outlier.MinimumSamples > 1000 ||
		value.Outlier.ConsecutiveFailures < 1 || value.Outlier.ConsecutiveFailures > 20 ||
		value.Outlier.FailureRatioPercent < 1 || value.Outlier.FailureRatioPercent > 100 ||
		value.Outlier.MaxEjectionPercent < 1 || value.Outlier.MaxEjectionPercent > 99 ||
		value.Outlier.BaseEjectionMS < 100 || value.Outlier.BaseEjectionMS > 60000 ||
		value.Outlier.MaxEjectionMS < value.Outlier.BaseEjectionMS || value.Outlier.MaxEjectionMS > 600000 ||
		value.Outlier.RecoveryProbeIntervalMS < 100 || value.Outlier.RecoveryProbeIntervalMS > 60000 {
		return nil, invalid("adaptive outlier bounds are invalid")
	}
	result := *value
	return &result, nil
}

func validateIngressFamilies(listeners []Listener, pools []Pool) error {
	for _, listener := range listeners {
		if listener.IngressSourceIPv4 == "" && listener.IngressSourceIPv6 == "" {
			continue
		}
		for _, pool := range pools {
			for _, endpoint := range pool.Endpoints {
				address, err := netip.ParseAddr(endpoint.Host)
				if err != nil {
					if listener.IngressSourceIPv4 == "" || listener.IngressSourceIPv6 == "" {
						return invalid("listener %q requires IPv4 and IPv6 sources for DNS endpoint %q", listener.ID, endpoint.ID)
					}
					continue
				}
				if address.Is4() && listener.IngressSourceIPv4 == "" {
					return invalid("listener %q lacks an IPv4 source for endpoint %q", listener.ID, endpoint.ID)
				}
				if address.Is6() && listener.IngressSourceIPv6 == "" {
					return invalid("listener %q lacks an IPv6 source for endpoint %q", listener.ID, endpoint.ID)
				}
			}
		}
	}
	return nil
}

func routeLess(left, right Route) bool {
	if left.Priority != right.Priority {
		return left.Priority > right.Priority
	}
	if len(left.PathPrefix) != len(right.PathPrefix) {
		return len(left.PathPrefix) > len(right.PathPrefix)
	}
	if (len(left.Hosts) > 0) != (len(right.Hosts) > 0) {
		return len(left.Hosts) > 0
	}
	if (len(left.NodeRegions) > 0) != (len(right.NodeRegions) > 0) {
		return len(left.NodeRegions) > 0
	}
	leftBits, rightBits := maxPrefixBits(left.ClientCIDRs), maxPrefixBits(right.ClientCIDRs)
	if leftBits != rightBits {
		return leftBits > rightBits
	}
	return left.ID < right.ID
}

func maxPrefixBits(values []string) int {
	maximum := -1
	for _, value := range values {
		prefix, _ := netip.ParsePrefix(value)
		if prefix.Bits() > maximum {
			maximum = prefix.Bits()
		}
	}
	return maximum
}

var routeHostPattern = regexp.MustCompile(`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizeRouteHosts(values []string) ([]string, error) {
	if len(values) > 100 {
		return nil, fmt.Errorf("host count exceeds 100")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(value)
		if len(value) > 253 || !routeHostPattern.MatchString(value) {
			return nil, fmt.Errorf("invalid host %q", value)
		}
		if slices.Contains(result, value) {
			return nil, fmt.Errorf("duplicate host %q", value)
		}
		result = append(result, value)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func normalizePathPrefix(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 2048 || value[0] != '/' || strings.ContainsAny(value, "\\?#%\x00\r\n\t") ||
		strings.Contains(value, "//") {
		return "", fmt.Errorf("path prefix must be canonical ASCII without query, fragment, encoding, or duplicate slash")
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "", fmt.Errorf("path prefix must be visible ASCII")
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("path prefix must not contain dot segments")
		}
	}
	// A trailing slash is kept: "/api/" matches "/api/..." only, "/api"
	// also "/api" itself (path segment prefix).
	return value, nil
}

func normalizeRegions(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, fmt.Errorf("region count exceeds 32")
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		value = strings.ToLower(value)
		if !validRegion(value) {
			return nil, fmt.Errorf("invalid region %q", value)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("duplicate region %q", value)
		}
		seen[value], result[index] = struct{}{}, value
	}
	sort.Strings(result)
	return result, nil
}

func validRegion(value string) bool {
	return tokenPattern.MatchString(strings.ToLower(value))
}

func normalizeCIDRs(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, fmt.Errorf("CIDR count exceeds 32")
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, fmt.Errorf("unsafe CIDR %q", value)
		}
		prefix = prefix.Masked()
		canonical := prefix.String()
		if canonical != value {
			return nil, fmt.Errorf("CIDR %q is not canonical", value)
		}
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("duplicate CIDR %q", canonical)
		}
		seen[canonical], result[index] = struct{}{}, canonical
	}
	sort.Strings(result)
	return result, nil
}

func parseSafeAddress(value string, allowUnspecified bool) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Is4In6() || address.Zone() != "" || address.IsMulticast() ||
		address == netip.MustParseAddr("255.255.255.255") || (!allowUnspecified && address.IsUnspecified()) {
		return netip.Addr{}, fmt.Errorf("address must be an unzoned unicast IP literal")
	}
	return address, nil
}

func parseOptionalSource(value string, wantIPv4 bool) (string, error) {
	if value == "" {
		return "", nil
	}
	address, err := parseSafeAddress(value, false)
	if err != nil || address.Is4() != wantIPv4 {
		return "", fmt.Errorf("source address family or safety is invalid")
	}
	return address.String(), nil
}

func normalizeHost(value string, allowDNS bool) (string, error) {
	value = strings.ToLower(value)
	if address, err := netip.ParseAddr(value); err == nil {
		if address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() ||
			address.Is4In6() || address.Zone() != "" || address == netip.MustParseAddr("255.255.255.255") {
			return "", fmt.Errorf("endpoint IP is unsafe")
		}
		return address.String(), nil
	}
	if allowDNS {
		return normalizeDNSHostname(value)
	}
	return "", fmt.Errorf("schema v1 endpoint host must be an IP literal")
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, arguments...))
}
