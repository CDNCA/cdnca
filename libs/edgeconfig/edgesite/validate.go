package edgesite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
)

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern     = regexp.MustCompile(`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	tokenPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	anchorPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexPattern32    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hexPattern16    = regexp.MustCompile(`^[0-9a-f]{16}$`)
	mimePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}(?:; ?charset=[A-Za-z0-9_-]{1,32})?$`)
	endpointPattern = regexp.MustCompile(`^https://[a-z0-9.-]{1,253}(?::[0-9]{1,5})?$`)
	// errorpagestyle.SourceHash: "sha256-" + base64 of 32 bytes.
	styleHashPattern = regexp.MustCompile(`^sha256-[A-Za-z0-9+/]{43}=$`)
)

func validUUID(value string) bool {
	return uuidPattern.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}
func validRevision(value int64) bool { return value >= 1 && value <= MaxSafeInteger }
func validName(value string) bool    { return len(value) <= 253 && namePattern.MatchString(value) }
func sortStrings(values []string)    { sort.Strings(values) }
func validPort(value int) bool       { return value >= 1 && value <= 65535 }
func sortedUniqueInts(values []int) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}
	return true
}

func sortedUniqueStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}
	return true
}

// Validate checks every field of site: identities, ranges, orderings (each
// list has one canonical order, so equal sites encode equally), internal
// references (pools, ports, names) and derived values (cache key prefix and
// freshness token). It does not fetch referenced objects.
func Validate(site Site) error {
	if site.Schema != Schema || !validUUID(site.ConfigurationScopeID) || !validUUID(site.TenantID) ||
		!validUUID(site.SiteID) || !validRevision(site.Revision) {
		return fmt.Errorf("%w: identity", ErrInvalid)
	}
	names, err := validateHosts(site.Hosts)
	if err != nil {
		return err
	}
	ports, err := validateListeners(site.Listeners)
	if err != nil {
		return err
	}
	if site.TrafficLimit != nil && (site.TrafficLimit.Period != "daily" && site.TrafficLimit.Period != "monthly" &&
		site.TrafficLimit.Period != "total" || len(site.TrafficLimit.NoticeHTML) > 64<<10) {
		return fmt.Errorf("%w: traffic limit", ErrInvalid)
	}
	if site.ForceHTTPS != nil && !ports[site.ForceHTTPS.RedirectPort] {
		return fmt.Errorf("%w: force_https port is not a TLS listener", ErrInvalid)
	}
	if forced := site.ForceHTTPS; forced != nil {
		if forced.Status != 0 && forced.Status != 302 && forced.Status != 307 && forced.Status != 308 {
			return fmt.Errorf("%w: force_https status", ErrInvalid)
		}
		for index, host := range forced.ExcludeHosts {
			if !names[host] || strings.HasPrefix(host, "*.") || index > 0 && forced.ExcludeHosts[index-1] >= host {
				return fmt.Errorf("%w: force_https exclude_hosts", ErrInvalid)
			}
		}
		if len(forced.ExcludeHosts) != 0 && len(forced.ExcludeHosts) == len(names) {
			return fmt.Errorf("%w: force_https excludes every name", ErrInvalid)
		}
	}
	// HSTS is the object's own hsts field; access never carries it.
	if site.Access != nil && site.Access.HSTS != nil {
		return fmt.Errorf("%w: access.hsts (use hsts)", ErrInvalid)
	}
	if site.Access != nil && edgeconfig.ValidateSiteAccess(*site.Access, append([]string{site.Hosts.Primary}, site.Hosts.Aliases...), len(ports) != 0) != nil {
		return fmt.Errorf("%w: access", ErrInvalid)
	}
	if site.Schedule302 != nil && (!sched302.ValidSite(*site.Schedule302) || !hasPlainListener(site.Listeners)) {
		return fmt.Errorf("%w: schedule302", ErrInvalid)
	}
	if err := validateOrigin(site.Origin); err != nil {
		return err
	}
	if err := validateSiteForwarding(site); err != nil {
		return err
	}
	if site.Cache != nil {
		if err := validateCache(site, names); err != nil {
			return err
		}
	}
	listenerPorts := make(map[int]bool, len(site.Listeners))
	for _, listener := range site.Listeners {
		listenerPorts[listener.Port] = true
	}
	if err := validateSecurity(site.Security, listenerPorts); err != nil {
		return err
	}
	if site.HTTP != nil && (site.HTTP.Kind != RefHTTPPolicy || !validRef(*site.HTTP, true)) {
		return fmt.Errorf("%w: http_policy", ErrInvalid)
	}
	if err := validateErrorPages(site.Errors); err != nil {
		return err
	}
	if err := validateErrorPageVariants(site.ErrorVariants); err != nil {
		return err
	}
	if site.Limits.MaxBodyBytes < 0 || site.Limits.MaxBodyBytes > MaxBodyBytes ||
		site.Limits.Connections != nil && (!validUUID(site.Limits.Connections.SubscriptionID) ||
			site.Limits.Connections.Max < -1 || site.Limits.Connections.Max > MaxConnections ||
			site.Limits.Connections.BandwidthBPS < 0 || site.Limits.Connections.BandwidthBPS > MaxBandwidthBPS ||
			site.Limits.Connections.MaxConnections < 0 || site.Limits.Connections.MaxConnections > MaxSubscriptionCount ||
			site.Limits.Connections.NewPerSecond < 0 || site.Limits.Connections.NewPerSecond > MaxSubscriptionCount ||
			site.Limits.Connections.QPS < 0 || site.Limits.Connections.QPS > MaxSubscriptionCount) {
		return fmt.Errorf("%w: limits", ErrInvalid)
	}
	if err := validateHSTS(site); err != nil {
		return err
	}
	if site.Telemetry != nil {
		if err := validateTelemetry(site); err != nil {
			return err
		}
	}
	return nil
}

// validateHosts returns every name the site serves.
func validateHosts(hosts Hosts) (map[string]bool, error) {
	if !validName(hosts.Primary) || hosts.Aliases == nil || len(hosts.Aliases)+1 > MaxNames ||
		!sortedUniqueStrings(hosts.Aliases) {
		return nil, fmt.Errorf("%w: hosts", ErrInvalid)
	}
	names := map[string]bool{hosts.Primary: true}
	for _, alias := range hosts.Aliases {
		if !validName(alias) || names[alias] {
			return nil, fmt.Errorf("%w: host alias", ErrInvalid)
		}
		names[alias] = true
	}
	return names, nil
}

// validateListeners returns the site's TLS ports.
func validateListeners(listeners []Listener) (map[int]bool, error) {
	if len(listeners) == 0 || len(listeners) > MaxListeners {
		return nil, fmt.Errorf("%w: listeners", ErrInvalid)
	}
	tlsPorts := map[int]bool{}
	for index, listener := range listeners {
		if !validPort(listener.Port) || index > 0 && listeners[index-1].Port >= listener.Port {
			return nil, fmt.Errorf("%w: listener ports must be unique and ascending", ErrInvalid)
		}
		switch listener.AddressFamily {
		case FamilyIPv4, FamilyIPv6, FamilyDualStack:
		default:
			return nil, fmt.Errorf("%w: listener address family", ErrInvalid)
		}
		if listener.TLS == nil {
			if listener.HTTP2 || listener.HTTP3 {
				return nil, fmt.Errorf("%w: listener %d: http2/http3 need TLS", ErrInvalid, listener.Port)
			}
			continue
		}
		protocols := listener.TLS.Protocols
		if !validUUID(listener.TLS.CertificateVersionID) || listener.TLS.CipherPreset == edgeconfig.TLSCipherModern {
			return nil, fmt.Errorf("%w: listener %d TLS", ErrInvalid, listener.Port)
		}
		profile := edgeconfig.TLSProfile{Protocols: protocols, CipherPreset: listener.TLS.CipherPreset,
			CipherSuites: listener.TLS.CipherSuites,
			OCSPStapling: listener.TLS.OCSPStapling, ClientAuth: listener.TLS.ClientAuth,
			PreferServerCiphers: listener.TLS.PreferServerCiphers}
		if ca := listener.TLS.ClientCA; ca != nil {
			if ca.Kind != RefClientCA || !validRef(*ca, true) {
				return nil, fmt.Errorf("%w: listener %d client CA", ErrInvalid, listener.Port)
			}
			profile.ClientCARef = "sha256:" + ca.SHA256
		}
		if protocols == nil || profile.Validate() != nil || listener.TLS.ClientAuth == edgeconfig.ClientAuthOff {
			return nil, fmt.Errorf("%w: listener %d TLS", ErrInvalid, listener.Port)
		}
		tls13 := slices.Contains(protocols, "TLSv1.3")
		if listener.HTTP3 && !tls13 {
			// QUIC is TLS 1.3 only: an h3 handshake of a 1.2-only site always fails.
			return nil, fmt.Errorf("%w: listener %d: http3 needs TLSv1.3", ErrInvalid, listener.Port)
		}
		tlsPorts[listener.Port] = true
	}
	return tlsPorts, nil
}

func validateOrigin(origin Origin) error {
	if len(origin.Pools) == 0 || len(origin.Pools) > MaxPools || origin.Routes == nil || len(origin.Routes) > MaxRoutes ||
		origin.Auth == nil || len(origin.Auth) > MaxOriginAuth {
		return fmt.Errorf("%w: origin", ErrInvalid)
	}
	if origin.FollowRedirect != nil {
		if err := origin.FollowRedirect.Validate(); err != nil {
			return err
		}
	}
	if err := validateEdgeOptions(origin); err != nil {
		return err
	}
	pools := make(map[string]Pool, len(origin.Pools))
	for index, pool := range origin.Pools {
		if index > 0 && origin.Pools[index-1].ID >= pool.ID {
			return fmt.Errorf("%w: pools must be sorted by id", ErrInvalid)
		}
		if err := validatePool(pool); err != nil {
			return err
		}
		pools[pool.ID] = pool
	}
	defaultPool, ok := pools[origin.DefaultPoolID]
	if !ok {
		return fmt.Errorf("%w: default pool", ErrInvalid)
	}
	if origin.DefaultFallbackPoolID != "" {
		if _, ok := pools[origin.DefaultFallbackPoolID]; !ok || origin.DefaultFallbackPoolID == origin.DefaultPoolID {
			return fmt.Errorf("%w: default fallback pool", ErrInvalid)
		}
	}
	if origin.L2 != nil {
		l2 := origin.L2
		fallback, ok := pools[l2.DirectFallbackPoolID]
		if defaultPool.Kind != PoolL2 || !ok || fallback.Kind != PoolOrigin ||
			l2.ProbeIntervalMS < 100 || l2.ProbeIntervalMS > 300000 || l2.FailureThreshold < 1 || l2.FailureThreshold > 20 ||
			l2.RecoveryThreshold < 1 || l2.RecoveryThreshold > 20 {
			return fmt.Errorf("%w: l2", ErrInvalid)
		}
		if err := ValidateL2Conditions(l2.Conditions, defaultPool); err != nil {
			return err
		}
	} else if defaultPool.Kind != PoolOrigin {
		return fmt.Errorf("%w: an l2 default pool needs l2 settings", ErrInvalid)
	}
	routeIDs := map[string]bool{}
	for _, route := range origin.Routes {
		if !tokenPattern.MatchString(route.ID) || routeIDs[route.ID] || route.Priority < -1000 || route.Priority > 1000 ||
			route.PathPrefix == "" && len(route.ClientCIDRs) == 0 && len(route.NodeRegions) == 0 && len(route.Hosts) == 0 ||
			len(route.Hosts) > MaxNames || !sortedUniqueStrings(route.Hosts) ||
			route.PathPrefix != "" && !validPathPrefix(route.PathPrefix) ||
			len(route.ClientCIDRs) > MaxRouteCIDRs || !sortedUniqueStrings(route.ClientCIDRs) ||
			len(route.NodeRegions) > MaxRouteRegions || !sortedUniqueStrings(route.NodeRegions) {
			return fmt.Errorf("%w: route", ErrInvalid)
		}
		routeIDs[route.ID] = true
		for _, cidr := range route.ClientCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || prefix != prefix.Masked() || prefix.String() != cidr || prefix.Addr().Is4In6() {
				return fmt.Errorf("%w: route client cidr", ErrInvalid)
			}
		}
		for _, host := range route.Hosts {
			if !validName(host) {
				return fmt.Errorf("%w: route host", ErrInvalid)
			}
		}
		for _, region := range route.NodeRegions {
			if !tokenPattern.MatchString(region) || region != strings.ToLower(region) {
				return fmt.Errorf("%w: route region", ErrInvalid)
			}
		}
		if _, ok := pools[route.PoolID]; !ok {
			return fmt.Errorf("%w: route pool", ErrInvalid)
		}
		if route.FallbackPoolID != "" {
			if _, ok := pools[route.FallbackPoolID]; !ok || route.FallbackPoolID == route.PoolID {
				return fmt.Errorf("%w: route fallback pool", ErrInvalid)
			}
		}
	}
	for index, auth := range origin.Auth {
		pool, ok := pools[auth.PoolID]
		if !ok || pool.Kind != PoolOrigin || index > 0 && origin.Auth[index-1].PoolID >= auth.PoolID ||
			!endpointPattern.MatchString(auth.Endpoint) || auth.Secret.Kind != RefOriginAuthSecret || !validRef(auth.Secret, false) {
			return fmt.Errorf("%w: origin auth", ErrInvalid)
		}
	}
	return nil
}

func validatePool(pool Pool) error {
	if !tokenPattern.MatchString(pool.ID) || pool.Kind != PoolOrigin && pool.Kind != PoolL2 ||
		len(pool.Endpoints) == 0 || len(pool.Endpoints) > MaxEndpoints {
		return fmt.Errorf("%w: pool %q", ErrInvalid, pool.ID)
	}
	switch pool.Algorithm {
	case "round_robin", "ip_hash", "url_hash", "least_conn", "random", "hash", "sticky":
	default:
		return fmt.Errorf("%w: pool %q algorithm", ErrInvalid, pool.ID)
	}
	if err := validatePoolForwarding(pool); err != nil {
		return err
	}
	retry := pool.Retry
	if len(retry.Methods) == 0 || len(retry.Methods) > 2 || !sortedUniqueStrings(retry.Methods) ||
		retry.MaxAttempts < 1 || retry.MaxAttempts > MaxRetryAttempts ||
		retry.ConnectTimeoutMS < 10 || retry.ConnectTimeoutMS > 60000 || retry.ReadTimeoutMS < 10 || retry.ReadTimeoutMS > 60000 ||
		retry.TotalBudgetMS < 10 || retry.TotalBudgetMS > 120000 {
		return fmt.Errorf("%w: pool %q retry", ErrInvalid, pool.ID)
	}
	for _, method := range retry.Methods {
		if method != "GET" && method != "HEAD" {
			return fmt.Errorf("%w: pool %q retry method", ErrInvalid, pool.ID)
		}
	}
	if idle := pool.KeepaliveIdleTimeoutMS; idle != nil && (pool.Kind != PoolOrigin || *idle != 0 && (*idle < 1000 || *idle > 300000)) {
		return fmt.Errorf("%w: pool %q keepalive", ErrInvalid, pool.ID)
	}
	ids := map[string]bool{}
	for _, endpoint := range pool.Endpoints {
		if !tokenPattern.MatchString(endpoint.ID) || ids[endpoint.ID] || !validOriginHost(endpoint.Host) ||
			!validPort(endpoint.Port) || endpoint.Weight < 1 || endpoint.Weight > 100 {
			return fmt.Errorf("%w: pool %q endpoint", ErrInvalid, pool.ID)
		}
		ids[endpoint.ID] = true
		switch endpoint.Scheme {
		case "http":
			if endpoint.SNI != "" || endpoint.SNIMode != "" || endpoint.TrustAnchor != "" {
				return fmt.Errorf("%w: plain endpoint %q with TLS settings", ErrInvalid, endpoint.ID)
			}
		case "https":
			if pool.Kind != PoolOrigin || endpoint.SNI != "" && !validOriginHost(endpoint.SNI) || !ValidTrustAnchor(endpoint.TrustAnchor) {
				return fmt.Errorf("%w: TLS endpoint %q needs a trust anchor", ErrInvalid, endpoint.ID)
			}
			switch endpoint.SNIMode {
			case "":
			case SNICustom:
				if endpoint.SNI == "" {
					return fmt.Errorf("%w: TLS endpoint %q custom SNI", ErrInvalid, endpoint.ID)
				}
			case SNIOriginHost, SNIVisitorHost:
				if endpoint.SNI != "" {
					return fmt.Errorf("%w: TLS endpoint %q SNI with sni_mode %s", ErrInvalid, endpoint.ID, endpoint.SNIMode)
				}
			default:
				return fmt.Errorf("%w: TLS endpoint %q sni_mode", ErrInvalid, endpoint.ID)
			}
		default:
			return fmt.Errorf("%w: endpoint %q scheme", ErrInvalid, endpoint.ID)
		}
		if pool.Kind == PoolL2 {
			if !validUUID(endpoint.NodeID) || !anchorPattern.MatchString(endpoint.MTLSIdentitySHA256) ||
				!validRevision(endpoint.TopologyRevision) {
				return fmt.Errorf("%w: l2 endpoint %q", ErrInvalid, endpoint.ID)
			}
		} else if endpoint.NodeID != "" || endpoint.MTLSIdentitySHA256 != "" || endpoint.TopologyRevision != 0 {
			return fmt.Errorf("%w: origin endpoint %q with l2 settings", ErrInvalid, endpoint.ID)
		}
	}
	return nil
}

func validOriginHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == value
	}
	return validName(value) && !strings.HasPrefix(value, "*.")
}

func validPathPrefix(value string) bool {
	// A trailing slash is meaningful: "/api/" matches "/api/..." only,
	// "/api" also matches "/api" itself (path segment prefix).
	if len(value) > 2048 || value[0] != '/' || strings.ContainsAny(value, "\\?#%") || strings.Contains(value, "//") {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validateCache(site Site, names map[string]bool) error {
	cache := site.Cache
	if cache.Policy.Rules == nil || cache.Policy.QueryNames == nil || cache.Policy.VaryHeaders == nil {
		return fmt.Errorf("%w: cache policy lists", ErrInvalid) // [] not null: one encoding per site
	}
	if !hexPattern32.MatchString(cache.KeyPrefix) || !hexPattern16.MatchString(cache.Generation) || !names[cache.Domain] ||
		cache.KeyPrefix != CacheKeyPrefix(site.TenantID, site.SiteID) {
		return fmt.Errorf("%w: cache identity", ErrInvalid)
	}
	generation, err := CacheGeneration(*cache)
	if err != nil || generation != cache.Generation {
		return fmt.Errorf("%w: cache generation", ErrInvalid)
	}
	domains := make([]string, 0, len(names))
	for name := range names {
		domains = append(domains, name)
	}
	if err := edgeconfig.ValidateSiteRuntimeCache(edgeconfig.SiteRuntimeCache{
		TenantID: site.TenantID, Domain: cache.Domain, Policy: cache.Policy, SharedAcrossDomains: !cache.KeyByHost,
	}, domains); err != nil {
		return fmt.Errorf("%w: cache policy: %v", ErrInvalid, err)
	}
	return nil
}

func validateSecurity(security Security, ports map[int]bool) error {
	if err := validateRulePlan(security.Rules, ports); err != nil {
		return err
	}
	if security.CC == nil || len(security.CC) > MaxCCBindings {
		return fmt.Errorf("%w: cc", ErrInvalid)
	}
	bound := map[int]bool{}
	for index, binding := range security.CC {
		if len(binding.Ports) == 0 || !sortedUniqueInts(binding.Ports) || binding.Policy.Kind != RefCCPolicy ||
			!validRef(binding.Policy, true) || !digestPattern.MatchString(binding.SourceSHA256) ||
			index > 0 && security.CC[index-1].Ports[0] >= binding.Ports[0] {
			return fmt.Errorf("%w: cc binding", ErrInvalid)
		}
		for _, port := range binding.Ports {
			if !ports[port] || bound[port] {
				return fmt.Errorf("%w: cc binding port %d", ErrInvalid, port)
			}
			bound[port] = true
		}
	}
	if security.Challenge != nil && (security.Challenge.Kind != RefChallenge || !validRef(*security.Challenge, false)) {
		return fmt.Errorf("%w: challenge", ErrInvalid)
	}
	if security.FirewallAction != nil && (security.FirewallAction.Kind != RefFirewallAction || !validRef(*security.FirewallAction, true)) {
		return fmt.Errorf("%w: firewall action", ErrInvalid)
	}
	if security.ManagedWAF != nil {
		if err := validateManagedWAF(*security.ManagedWAF); err != nil {
			return err
		}
	}
	if len(security.Mounts) > MaxRuleMounts || (len(security.Mounts) == 0) != (security.ResolvedSHA256 == "") ||
		security.ResolvedSHA256 != "" && !digestPattern.MatchString(security.ResolvedSHA256) {
		return fmt.Errorf("%w: mounts", ErrInvalid)
	}
	for _, mount := range security.Mounts {
		if mount.PackID == "" || len(mount.PackID) > 160 || mount.Version == "" || mount.Engine == "" ||
			!digestPattern.MatchString(mount.SHA256) || mount.Params == nil ||
			mount.Layer != "system" && mount.Layer != "developer" && mount.Layer != "user" {
			return fmt.Errorf("%w: mount", ErrInvalid)
		}
	}
	return nil
}

// validRef: id is a UUID, revision positive; sha256 required when
// withDigest, otherwise optional.
func validRef(ref Ref, withDigest bool) bool {
	return validUUID(ref.ID) && validRevision(ref.Revision) &&
		(ref.SHA256 == "" && !withDigest || digestPattern.MatchString(ref.SHA256))
}

// ManagedWAFFromEdge is the v2 form of a normalized v7 managed WAF.
func ManagedWAFFromEdge(value edgeconfig.ManagedWAF) ManagedWAF {
	result := ManagedWAF{
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion,
		Profile: ManagedWAFProfile{
			RequestBodyLimit: value.RequestBodyLimit, RequestBodyNoFilesLimit: value.RequestBodyNoFilesLimit,
			RequestBodyLimitAction: value.RequestBodyLimitAction, ArgumentsLimit: value.ArgumentsLimit,
			JSONDepthLimit: value.JSONDepthLimit, PCREMatchLimit: value.PCREMatchLimit,
			InspectionLimitAction: value.InspectionLimitAction,
		},
		CRSProfile: value.Profile, Exclusions: value.Exclusions, AllowCIDRs: value.AllowCIDRs, Apps: value.Apps,
	}
	if result.Exclusions == nil {
		result.Exclusions = []int{}
	}
	if result.AllowCIDRs == nil {
		result.AllowCIDRs = []string{}
	}
	return result
}

// Edge is the v7 form (edgeconfig.ManagedWAF), for its validator.
func (value ManagedWAF) Edge() edgeconfig.ManagedWAF {
	return edgeconfig.ManagedWAF{
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion,
		RequestBodyLimit: value.Profile.RequestBodyLimit, RequestBodyNoFilesLimit: value.Profile.RequestBodyNoFilesLimit,
		RequestBodyLimitAction: value.Profile.RequestBodyLimitAction, ArgumentsLimit: value.Profile.ArgumentsLimit,
		JSONDepthLimit: value.Profile.JSONDepthLimit, PCREMatchLimit: value.Profile.PCREMatchLimit,
		InspectionLimitAction: value.Profile.InspectionLimitAction,
		Profile:               value.CRSProfile, Exclusions: value.Exclusions, AllowCIDRs: value.AllowCIDRs, Apps: value.Apps,
	}
}

func validateManagedWAF(value ManagedWAF) error {
	if value.Exclusions == nil || value.AllowCIDRs == nil {
		return fmt.Errorf("%w: managed WAF lists", ErrInvalid)
	}
	normalized, err := edgeconfig.CanonicalListenerManagedWAF(value.Edge())
	if err != nil {
		return fmt.Errorf("%w: managed WAF: %v", ErrInvalid, err)
	}
	got, _ := json.Marshal(value)
	want, _ := json.Marshal(ManagedWAFFromEdge(*normalized))
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%w: managed WAF is not normalized", ErrInvalid)
	}
	return nil
}

// ErrorCategoryAllows is errorpage.categoryAllowsStatus for the categories a
// site carries: origin responses and edge refusals 400-599, connection
// failures 502-504.
func ErrorCategoryAllows(category string, status int) bool {
	switch category {
	case ErrorOriginResponse, ErrorEdgeRoute:
		return status >= 400 && status <= 599
	case ErrorEdgeConnect:
		return status >= 502 && status <= 504
	}
	return false
}

func validErrorPageMIME(value string) bool { return slices.Contains(ErrorPageMIMETypes, value) }

func validStyleHash(mime, value string) bool {
	return value == "" || mime == "text/html" && styleHashPattern.MatchString(value)
}

func validateHSTS(site Site) error {
	hsts := site.HSTS
	if hsts == nil {
		return nil
	}
	tls := false
	for _, listener := range site.Listeners {
		tls = tls || listener.TLS != nil
	}
	if !tls || hsts.MaxAgeSeconds < 0 || hsts.MaxAgeSeconds > MaxHSTSMaxAge ||
		hsts.Preload && (!hsts.IncludeSubdomains || hsts.MaxAgeSeconds < HSTSPreloadMinAge) {
		return fmt.Errorf("%w: hsts", ErrInvalid)
	}
	return nil
}

func validateErrorPages(pages []ErrorPage) error {
	if pages == nil || len(pages) > MaxErrorPages {
		return fmt.Errorf("%w: error pages", ErrInvalid)
	}
	for index, page := range pages {
		if !ErrorCategoryAllows(page.Category, page.Status) || !tokenPattern.MatchString(page.RuleID) ||
			!validErrorPageMIME(page.MIMEType) || !validStyleHash(page.MIMEType, page.StyleHash) ||
			page.Asset.Kind != RefErrorPageAsset || !validRef(page.Asset, true) {
			return fmt.Errorf("%w: error page", ErrInvalid)
		}
		if index > 0 {
			previous := pages[index-1]
			if previous.Category > page.Category || previous.Category == page.Category && previous.Status >= page.Status {
				return fmt.Errorf("%w: error pages must be sorted by (category, status) and unique", ErrInvalid)
			}
		}
	}
	return nil
}

// variantRegionPattern is siteobject's node page region form.
var variantRegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrorPageVariantKey orders variants: category, status, node, region.
func ErrorPageVariantKey(variant ErrorPageVariant) string {
	return fmt.Sprintf("%s\x00%03d\x00%s\x00%s", variant.Category, variant.Status, variant.NodeID, variant.Region)
}

func validateErrorPageVariants(variants []ErrorPageVariant) error {
	if len(variants) > MaxErrorPageVariants {
		return fmt.Errorf("%w: %d error page variants exceed %d", ErrInvalid, len(variants), MaxErrorPageVariants)
	}
	for index, variant := range variants {
		if variant.Category != ErrorEdgeConnect || !ErrorCategoryAllows(variant.Category, variant.Status) ||
			(variant.Region == "") == (variant.NodeID == "") ||
			variant.Region != "" && !variantRegionPattern.MatchString(variant.Region) ||
			variant.NodeID != "" && !validUUID(variant.NodeID) ||
			!tokenPattern.MatchString(variant.RuleID) || !validErrorPageMIME(variant.MIMEType) ||
			!validStyleHash(variant.MIMEType, variant.StyleHash) ||
			variant.Asset.Kind != RefErrorPageAsset || !validRef(variant.Asset, true) {
			return fmt.Errorf("%w: error page variant", ErrInvalid)
		}
		if index > 0 && ErrorPageVariantKey(variants[index-1]) >= ErrorPageVariantKey(variant) {
			return fmt.Errorf("%w: error page variants must be sorted and unique", ErrInvalid)
		}
	}
	return nil
}

func validateTelemetry(site Site) error {
	telemetry := site.Telemetry
	if telemetry.PackageSubscriptionID != "" && !validUUID(telemetry.PackageSubscriptionID) {
		return fmt.Errorf("%w: telemetry subscription", ErrInvalid)
	}
	capture := telemetry.Capture
	if capture.Methods == nil || capture.URIPrefixes == nil {
		return fmt.Errorf("%w: telemetry capture lists", ErrInvalid)
	}
	policy := edgeconfig.TelemetrySiteCapturePolicy{
		SiteID: site.SiteID, Domain: site.Hosts.Primary, ListenPort: uint16(site.Listeners[0].Port),
		Revision: capture.Revision, EvidenceDigest: capture.EvidenceDigest, Enabled: capture.Enabled,
		Methods: capture.Methods, URIPrefixes: capture.URIPrefixes,
		RequestHeaderAllowlist: capture.RequestHeaderAllowlist, ResponseHeaderAllowlist: capture.ResponseHeaderAllowlist,
		RequestBodyFieldAllowlist: capture.RequestBodyFieldAllowlist, ResponseBodyFieldAllowlist: capture.ResponseBodyFieldAllowlist,
		MaxValueBytes: capture.MaxValueBytes, MaxBodyBytes: capture.MaxBodyBytes, MaxEventBytes: capture.MaxEventBytes,
	}
	if _, err := edgeconfig.TelemetryCapturePolicyFromManifest(policy); err != nil {
		return fmt.Errorf("%w: telemetry capture: %v", ErrInvalid, err)
	}
	return nil
}

// hasPlainListener: scheduled requests land on plain HTTP.
func hasPlainListener(listeners []Listener) bool {
	for _, listener := range listeners {
		if listener.TLS == nil {
			return true
		}
	}
	return false
}

// Validate checks the hop bound.
func (redirect FollowRedirect) Validate() error {
	if redirect.MaxHops < 1 || redirect.MaxHops > MaxFollowRedirectHops {
		return fmt.Errorf("%w: follow_redirect.max_hops", ErrInvalid)
	}
	return nil
}

// validateEdgeOptions: the site edit options of the origin (SITE_EDGE_OPTIONS).
func validateEdgeOptions(origin Origin) error {
	if engine := origin.SearchEngine; engine != nil {
		found := false
		for _, pool := range origin.Pools {
			found = found || pool.ID == engine.PoolID && pool.Kind == PoolOrigin
		}
		if !found || engine.PoolID == origin.DefaultPoolID || len(engine.Tokens) > 32 || !sortedUniqueStrings(engine.Tokens) {
			return fmt.Errorf("%w: search_engine", ErrInvalid)
		}
		for _, token := range engine.Tokens {
			if len(token) < 3 || len(token) > 64 || token != strings.ToLower(token) || strings.ContainsAny(token, " \t\r\n") {
				return fmt.Errorf("%w: search_engine token", ErrInvalid)
			}
		}
	}
	if len(origin.Unbuffered) > 2 || !sortedUniqueStrings(origin.Unbuffered) {
		return fmt.Errorf("%w: unbuffered", ErrInvalid)
	}
	for _, direction := range origin.Unbuffered {
		if direction != UnbufferedRequest && direction != UnbufferedResponse {
			return fmt.Errorf("%w: unbuffered", ErrInvalid)
		}
	}
	return nil
}

var (
	l2RuleFields    = []string{"host", "protocol", "request_uri", "uri"}
	l2RuleOperators = []string{"contains", "eq", "neq", "not_contains", "not_regex", "prefix", "regex", "suffix"}
)

// ValidateL2Conditions: conditions sorted by id, their endpoints sorted, in
// the L2 pool, in no other condition.
func ValidateL2Conditions(conditions []L2Condition, pool Pool) error {
	endpoints := make(map[string]bool, len(pool.Endpoints))
	for _, endpoint := range pool.Endpoints {
		endpoints[endpoint.ID] = false
	}
	for index, condition := range conditions {
		if !tokenPattern.MatchString(condition.ID) || index > 0 && conditions[index-1].ID >= condition.ID ||
			len(condition.Rules) > MaxL2Rules ||
			len(condition.NodeIDs) > MaxL2ConditionNodes || !sortedUniqueStrings(condition.NodeIDs) ||
			len(condition.EndpointIDs) == 0 || !sortedUniqueStrings(condition.EndpointIDs) {
			return fmt.Errorf("%w: l2 condition", ErrInvalid)
		}
		for _, nodeID := range condition.NodeIDs {
			if !validUUID(nodeID) {
				return fmt.Errorf("%w: l2 condition node", ErrInvalid)
			}
		}
		for _, id := range condition.EndpointIDs {
			if used, ok := endpoints[id]; !ok || used {
				return fmt.Errorf("%w: l2 condition endpoint %q", ErrInvalid, id)
			}
			endpoints[id] = true
		}
		for _, rule := range condition.Rules {
			if !slices.Contains(l2RuleFields, rule.Field) || !slices.Contains(l2RuleOperators, rule.Operator) ||
				rule.Value == "" || len(rule.Value) > MaxL2RuleValueBytes || hasControlByte(rule.Value) {
				return fmt.Errorf("%w: l2 condition rule", ErrInvalid)
			}
			if rule.Operator == "regex" || rule.Operator == "not_regex" {
				// RE2 (no backreferences or lookaround) in printable ASCII
				// means the same under the node's PCRE (L2-REGEX-01)
				if _, err := regexp.Compile(rule.Value); err != nil || !printableASCII(rule.Value) {
					return fmt.Errorf("%w: l2 condition regex", ErrInvalid)
				}
			}
		}
	}
	return nil
}

func hasControlByte(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

// UsesL2Routing reports whether the site needs L2_ROUTING.
func (site Site) UsesL2Routing() bool {
	return site.Origin.L2 != nil && (site.Origin.L2.CacheOnly || len(site.Origin.L2.Conditions) != 0 || site.Origin.L2.Passthrough)
}

// UsesTLSOptions reports whether the site needs SITE_TLS_OPTIONS: a TLS
// listener with HTTP/2 off or an explicit prefer_server_ciphers.
func (site Site) UsesTLSOptions() bool {
	for _, listener := range site.Listeners {
		if listener.TLS != nil && (!listener.HTTP2 || listener.TLS.PreferServerCiphers != nil) {
			return true
		}
	}
	return false
}

// UsesTLSCustomCiphers reports whether the site needs
// SITE_TLS_CUSTOM_CIPHERS: a TLS listener with the custom cipher preset.
func (site Site) UsesTLSCustomCiphers() bool {
	for _, listener := range site.Listeners {
		if listener.TLS != nil && listener.TLS.CipherPreset == edgeconfig.TLSCipherCustom {
			return true
		}
	}
	return false
}

// UsesEdgeOptions reports whether the site needs SITE_EDGE_OPTIONS.
func (site Site) UsesEdgeOptions() bool {
	return site.Default || site.Origin.SearchEngine != nil || site.Origin.ACMEPassthrough || len(site.Origin.Unbuffered) != 0
}
