package edgesite

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Origin forwarding (ge-origin G3; agents/edge-agent/internal/siteruntimev2
// origin_forwarding.go is the v7 side and the source of these rules): the
// pool's balancing extras (hash key, sticky token), the origin Host, port
// following, backup endpoints, per-endpoint connection bounds, trusted
// proxies of the client address headers, the WebSocket Origin allowlist and
// the TLS listeners' pool.

const MaxEndpointConns = 100000

var (
	hashKeyPattern      = regexp.MustCompile(`^[A-Za-z0-9._:/|@=$-]{1,256}$`)
	hashKeyToken        = regexp.MustCompile(`\$[a-z_][a-z0-9_]*`)
	hashKeyDynamic      = regexp.MustCompile(`^\$(cookie|arg|http)_[a-z0-9_]{1,64}$`)
	stickyNamePattern   = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	webSocketOriginExpr = regexp.MustCompile(`^https?://[a-z0-9.\-\[\]:]{1,262}$`)
	// HashKeyVariables are the request variables a hash key may name (besides
	// $cookie_*, $arg_*, $http_*).
	HashKeyVariables = []string{"$remote_addr", "$binary_remote_addr", "$host", "$uri", "$request_uri", "$args", "$scheme", "$request_method"}
)

// ValidHashKey: a template of literal text and allowed variables, with at
// least one variable.
func ValidHashKey(key string) bool {
	if !hashKeyPattern.MatchString(key) {
		return false
	}
	tokens := hashKeyToken.FindAllString(key, -1)
	if len(tokens) == 0 || strings.Count(key, "$") != len(tokens) {
		return false
	}
	for _, token := range tokens {
		if !slices.Contains(HashKeyVariables, token) && !hashKeyDynamic.MatchString(token) {
			return false
		}
	}
	return true
}

// StickyToken is the value pinning a visitor to an endpoint of a sticky
// pool: the same bytes as v7 (siteruntimev2.stickyToken), stable while the
// endpoint keeps its ID and revealing nothing about it.
func StickyToken(siteID, poolID, endpointID string) string {
	digest := sha256.Sum256([]byte("cdnca-sticky-v1\x00" + siteID + "\x00" + poolID + "\x00" + endpointID))
	return hex.EncodeToString(digest[:12])
}

// validRequestHostValue: host[:port], an IPv4 address, or [IPv6][:port].
func validRequestHostValue(value string) bool {
	host, port := value, ""
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 {
			return false
		}
		address, err := netip.ParseAddr(value[1:end])
		if err != nil || !address.Is6() || address.String() != value[1:end] {
			return false
		}
		rest := value[end+1:]
		if rest == ":" || rest != "" && !strings.HasPrefix(rest, ":") {
			return false
		}
		port = strings.TrimPrefix(rest, ":")
	} else {
		if index := strings.LastIndex(value, ":"); index >= 0 {
			host, port = value[:index], value[index+1:]
			if port == "" {
				return false
			}
		}
		if address, err := netip.ParseAddr(host); err == nil {
			if !address.Is4() {
				return false
			}
		} else if !validName(host) || strings.HasPrefix(host, "*.") {
			return false
		}
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || !validPort(number) || strconv.Itoa(number) != port {
			return false
		}
	}
	return true
}

func validatePoolForwarding(pool Pool) error {
	fail := func(what string) error { return fmt.Errorf("%w: pool %q %s", ErrInvalid, pool.ID, what) }
	switch pool.Algorithm {
	case "hash":
		if !ValidHashKey(pool.HashKey) || pool.Sticky != nil {
			return fail("hash_key")
		}
	case "sticky":
		if pool.Sticky == nil || pool.HashKey != "" || !stickyNamePattern.MatchString(pool.Sticky.Name) ||
			pool.Sticky.Source != "cookie" && pool.Sticky.Source != "header" && pool.Sticky.Source != "arg" {
			return fail("sticky")
		}
	default:
		if pool.HashKey != "" || pool.Sticky != nil {
			return fail("hash_key/sticky")
		}
	}
	if pool.Kind != PoolOrigin && (pool.Algorithm == "hash" || pool.Algorithm == "sticky" || pool.RequestHost != nil || pool.FollowPort) {
		return fail("forwarding on an l2 pool")
	}
	if host := pool.RequestHost; host != nil {
		switch host.Mode {
		case RequestHostOrigin, RequestHostVisitorPort:
			if host.Value != "" {
				return fail("request_host")
			}
		case RequestHostCustom:
			if !validRequestHostValue(host.Value) {
				return fail("request_host")
			}
		default:
			return fail("request_host")
		}
	}
	if pool.FollowPort && (pool.Algorithm == "sticky" || pool.RequestHost != nil && pool.RequestHost.Mode == RequestHostOrigin) {
		return fail("follow_port")
	}
	primaries := 0
	for _, endpoint := range pool.Endpoints {
		if endpoint.MaxConns < 0 || endpoint.MaxConns > MaxEndpointConns {
			return fail("max_conns")
		}
		if endpoint.Level < 0 || endpoint.Level > MaxLevel || endpoint.Level != 0 && pool.Kind != PoolOrigin {
			return fail("level")
		}
		if endpoint.Level == 0 {
			primaries++
		}
	}
	// The node's selector walks levels for any algorithm (cdnca_origin.lua).
	if primaries == 0 {
		return fail("level")
	}
	if pool.ActiveLevel < 0 || pool.ActiveLevel > MaxLevel || pool.ActiveLevel != 0 && pool.Kind != PoolOrigin {
		return fail("active_level")
	}
	return nil
}

func validateSiteForwarding(site Site) error {
	origin := site.Origin
	if !sortedUniqueStrings(origin.TrustedProxyCIDRs) || len(origin.TrustedProxyCIDRs) > 64 {
		return fmt.Errorf("%w: trusted_proxy_cidrs", ErrInvalid)
	}
	for _, raw := range origin.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Masked() != prefix || prefix.String() != raw || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return fmt.Errorf("%w: trusted proxy %q", ErrInvalid, raw)
		}
	}
	if len(site.WebSocketOrigins) != 0 {
		if !site.WebSocket || len(site.WebSocketOrigins) > 64 || !sortedUniqueStrings(site.WebSocketOrigins) {
			return fmt.Errorf("%w: websocket_origins", ErrInvalid)
		}
		for _, value := range site.WebSocketOrigins {
			if !webSocketOriginExpr.MatchString(value) {
				return fmt.Errorf("%w: websocket origin %q", ErrInvalid, value)
			}
		}
	}
	if origin.HTTPSPoolID != "" {
		var pool *Pool
		for index := range origin.Pools {
			if origin.Pools[index].ID == origin.HTTPSPoolID {
				pool = &origin.Pools[index]
			}
		}
		tls := false
		for _, listener := range site.Listeners {
			tls = tls || listener.TLS != nil
		}
		valid := pool != nil && pool.Kind == PoolOrigin && pool.ID != origin.DefaultPoolID && tls &&
			(origin.L2 == nil || origin.L2.DirectFallbackPoolID != pool.ID)
		for _, endpoint := range pool.endpoints() {
			valid = valid && endpoint.Scheme == "https"
		}
		if !valid {
			return fmt.Errorf("%w: https_pool_id", ErrInvalid)
		}
	}
	return nil
}

func (pool *Pool) endpoints() []Endpoint {
	if pool == nil {
		return nil
	}
	return pool.Endpoints
}
