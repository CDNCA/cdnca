package site

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// Origin forwarding settings (migration 367): how the
// edge reaches a site's origins. Every value is validated here; the edge
// renders them without further interpretation.

// HashKeyVariables are the nginx variables a BalanceHash key may use. Only
// request values: nothing the edge computes later (upstream, cache) and
// nothing that names other sites.
var HashKeyVariables = []string{
	"$remote_addr", "$binary_remote_addr", "$host", "$uri", "$request_uri", "$args", "$scheme", "$request_method",
}

var (
	hashKeyDynamicPattern = regexp.MustCompile(`^\$(cookie|arg|http)_[a-z0-9_]{1,64}$`)
	hashKeyTokenPattern   = regexp.MustCompile(`\$[a-z_][a-z0-9_]*`)
	hashKeyLiteralPattern = regexp.MustCompile(`^[A-Za-z0-9._:/|@=-]*$`)
	stickyNamePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

const (
	maxWebSocketOrigins  = 64
	maxTrustedProxyCIDRs = 64
	maxOriginCABytes     = 65536
	maxOriginMaxConns    = 100_000
)

var healthCheckPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,255}$`)

// normalizeOriginForwarding validates and canonicalizes pool's forwarding
// settings in place; normalizeOriginPool calls it after the origins.
func normalizeOriginForwarding(pool *OriginPool) error {
	if err := normalizeSiteEdgeOptions(pool); err != nil {
		return err
	}
	if redirect := pool.FollowRedirect; redirect != nil {
		if redirect.MaxHops == 0 {
			redirect.MaxHops = DefaultFollowRedirectHops
		}
		if redirect.MaxHops < 1 || redirect.MaxHops > MaxFollowRedirectHops {
			return ErrInvalidInput
		}
	}
	switch pool.BalanceMethod {
	case BalanceHash:
		key, err := normalizeHashKey(pool.HashKey)
		if err != nil || pool.Sticky != nil {
			return ErrInvalidInput
		}
		pool.HashKey = key
	case BalanceSticky:
		if pool.HashKey != "" || pool.Sticky == nil || !stickyNamePattern.MatchString(pool.Sticky.Name) {
			return ErrInvalidInput
		}
		switch pool.Sticky.Source {
		case OriginStickyCookie, OriginStickyArg:
			pool.Sticky.Name = strings.ToLower(pool.Sticky.Name)
		case OriginStickyHeader:
			// nginx exposes request headers as $http_<lower, - as _>.
			pool.Sticky.Name = strings.ToLower(pool.Sticky.Name)
		default:
			return ErrInvalidInput
		}
	default:
		if pool.HashKey != "" || pool.Sticky != nil {
			return ErrInvalidInput
		}
	}

	switch pool.RequestHost.Mode {
	case "":
		pool.RequestHost = OriginRequestHost{Mode: OriginRequestHostVisitor}
	case OriginRequestHostVisitor, OriginRequestHostVisitorPort, OriginRequestHostOrigin:
		if pool.RequestHost.Value != "" {
			return ErrInvalidInput
		}
		if pool.RequestHost.Mode == OriginRequestHostOrigin && !originHostsShared(pool.Origins) &&
			pool.BalanceMethod != BalanceRoundRobin && pool.BalanceMethod != BalanceRandom && pool.BalanceMethod != BalanceSticky {
			// Origins naming different hosts are chosen per request before
			// the Host is set: weighted (round robin / random) or sticky.
			return ErrInvalidInput
		}
	case OriginRequestHostCustom:
		host, err := normalizeRequestHost(pool.RequestHost.Value)
		if err != nil {
			return ErrInvalidInput
		}
		pool.RequestHost.Value = host
	default:
		return ErrInvalidInput
	}

	defaultOriginPorts(pool)
	if pool.TLS.Trust == "" {
		pool.TLS.Trust = OriginTrustSystem
	}
	// Each scheme uses only its own ports (HTTP 回源端口 / HTTPS 回源端口 in
	// the console); 跟随协议和端口 uses neither.
	if pool.HTTPPort < 1 || pool.HTTPPort > 65_535 || pool.HTTPSPort < 1 || pool.HTTPSPort > 65_535 ||
		pool.Scheme == OriginSchemeHTTP && pool.HTTPSPort != 443 || pool.Scheme == OriginSchemeHTTPS && pool.HTTPPort != 80 ||
		pool.Scheme == OriginSchemeFollow && pool.FollowPort && (pool.HTTPPort != 80 || pool.HTTPSPort != 443) {
		return ErrInvalidInput
	}
	switch pool.Scheme {
	case OriginSchemeHTTP:
		if pool.TLS.SNI != "" || pool.TLS.Trust != OriginTrustSystem || pool.TLS.CAPEM != "" {
			return ErrInvalidInput
		}
	case OriginSchemeHTTPS, OriginSchemeFollow:
		if pool.TLS.SNI != "" {
			sni, err := normalizeDomain(strings.ToLower(pool.TLS.SNI), false)
			if err != nil {
				return ErrInvalidInput
			}
			pool.TLS.SNI = sni
		}
		switch pool.TLS.Trust {
		case OriginTrustSystem, OriginTrustNone:
			if pool.TLS.CAPEM != "" {
				return ErrInvalidInput
			}
		case OriginTrustCustom:
			ca, err := normalizeOriginCA(pool.TLS.CAPEM)
			if err != nil {
				return ErrInvalidInput
			}
			pool.TLS.CAPEM = ca
		default:
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	if pool.FollowPort && (pool.BalanceMethod == BalanceSticky || pool.RequestHost.Mode == OriginRequestHostOrigin) {
		// The edge renders one upstream per port or one per origin.
		return ErrInvalidInput
	}
	// follow with FollowPort (跟随协议和端口): both protocols on the visitor's port.
	if pool.OriginAuthEnabled == nil {
		on := true
		pool.OriginAuthEnabled = &on
	}

	if pool.WebSocket == nil {
		pool.WebSocket = &OriginWebSocket{Enabled: true}
	}
	origins, err := normalizeWebSocketOrigins(pool.WebSocket.AllowedOrigins)
	if err != nil || !pool.WebSocket.Enabled && len(origins) != 0 {
		return ErrInvalidInput
	}
	pool.WebSocket.AllowedOrigins = origins

	cidrs, err := normalizeTrustedProxyCIDRs(pool.TrustedProxyCIDRs)
	if err != nil {
		return ErrInvalidInput
	}
	pool.TrustedProxyCIDRs = cidrs

	switch pool.FailbackMode {
	case "":
		pool.FailbackMode = FailbackAuto
	case FailbackAuto, FailbackManual:
	default:
		return ErrInvalidInput
	}
	if pool.HealthCheckPath == "" {
		pool.HealthCheckPath = "/"
	}
	if !healthCheckPathPattern.MatchString(pool.HealthCheckPath) {
		return ErrInvalidInput
	}
	primary := 0
	for _, origin := range pool.Origins {
		if origin.MaxConns < 0 || origin.MaxConns > maxOriginMaxConns ||
			origin.Level < 0 || origin.Level > MaxOriginLevel {
			return ErrInvalidInput
		}
		if origin.Enabled && origin.Level == 0 {
			primary++
		}
	}
	if primary == 0 {
		return ErrInvalidInput
	}
	// Any balance method may have backup levels: dynamic routing (the only
	// node mode since d13-c3b) walks the levels for every algorithm
	// (cdnca_origin.lua).
	return nil
}

// defaultOriginPorts fills the scheme and the pool's ports with their
// defaults (http, 80, 443).
func defaultOriginPorts(pool *OriginPool) {
	if pool.Scheme == "" {
		pool.Scheme = OriginSchemeHTTP
	}
	if pool.HTTPPort == 0 {
		pool.HTTPPort = 80
	}
	if pool.HTTPSPort == 0 {
		pool.HTTPSPort = 443
	}
}

// inheritedOriginPort is the port of an origin without its own: HTTPSPort
// for https, else HTTPPort (follow's HTTPS visits use HTTPSPort anyway).
func inheritedOriginPort(pool OriginPool) int {
	if pool.Scheme == OriginSchemeHTTPS {
		return pool.HTTPSPort
	}
	return pool.HTTPPort
}

// inheritOriginPorts sets every PortInherited origin's Port to the pool's
// (before the origins are validated; defaults applied).
func inheritOriginPorts(pool *OriginPool) {
	defaultOriginPorts(pool)
	for index := range pool.Origins {
		if pool.Origins[index].PortInherited {
			pool.Origins[index].Port = inheritedOriginPort(*pool)
		}
	}
}

func originHostsShared(origins []Origin) bool {
	for _, origin := range origins {
		if origin.Host != origins[0].Host {
			return false
		}
	}
	return true
}

func normalizeHashKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" || len(key) > 256 {
		return "", ErrInvalidInput
	}
	tokens := hashKeyTokenPattern.FindAllStringIndex(key, -1)
	if len(tokens) == 0 {
		return "", ErrInvalidInput
	}
	previous := 0
	for _, token := range tokens {
		if !hashKeyLiteralPattern.MatchString(key[previous:token[0]]) {
			return "", ErrInvalidInput
		}
		name := key[token[0]:token[1]]
		if !slices.Contains(HashKeyVariables, name) && !hashKeyDynamicPattern.MatchString(name) {
			return "", ErrInvalidInput
		}
		previous = token[1]
	}
	if !hashKeyLiteralPattern.MatchString(key[previous:]) || strings.Contains(key, "${") {
		return "", ErrInvalidInput
	}
	return key, nil
}

// normalizeRequestHost accepts a host name or IP address with an optional
// port; IPv6 addresses are bracketed.
func normalizeRequestHost(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 259 || strings.ContainsAny(value, "$/\\?#@ \t\r\n\"'{};") {
		return "", ErrInvalidInput
	}
	host, port := value, ""
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 {
			return "", ErrInvalidInput
		}
		host, port = value[1:end], strings.TrimPrefix(value[end+1:], ":")
		if value[end+1:] != "" && !strings.HasPrefix(value[end+1:], ":") {
			return "", ErrInvalidInput
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() || address.Zone() != "" {
			return "", ErrInvalidInput
		}
		host = "[" + address.String() + "]"
	} else {
		if index := strings.LastIndex(value, ":"); index >= 0 {
			host, port = value[:index], value[index+1:]
		}
		if address, err := netip.ParseAddr(host); err == nil {
			if !address.Is4() {
				return "", ErrInvalidInput
			}
			host = address.String()
		} else if normalized, err := normalizeDomain(host, false); err == nil {
			host = normalized
		} else {
			return "", ErrInvalidInput
		}
	}
	if port == "" {
		if strings.HasSuffix(value, ":") {
			return "", ErrInvalidInput
		}
		return host, nil
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65_535 || strconv.Itoa(number) != port {
		return "", ErrInvalidInput
	}
	return host + ":" + port, nil
}

// normalizeOriginCA accepts one to 32 PEM CA certificates.
func normalizeOriginCA(raw string) (string, error) {
	if raw == "" || len(raw) > maxOriginCABytes {
		return "", ErrInvalidInput
	}
	rest := []byte(raw)
	var output bytes.Buffer
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", ErrInvalidInput
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return "", ErrInvalidInput
		}
		if err := pem.Encode(&output, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return "", ErrInvalidInput
		}
		count++
		rest = remainder
	}
	if count == 0 || count > 32 {
		return "", ErrInvalidInput
	}
	return output.String(), nil
}

func normalizeWebSocketOrigins(values []string) ([]string, error) {
	if len(values) > maxWebSocketOrigins {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		parsed, err := url.Parse(strings.ToLower(strings.TrimSpace(raw)))
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil ||
			parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
			return nil, ErrInvalidInput
		}
		host := parsed.Hostname()
		if address, err := netip.ParseAddr(host); err == nil {
			if address.Zone() != "" {
				return nil, ErrInvalidInput
			}
		} else if _, err := normalizeDomain(host, false); err != nil {
			return nil, ErrInvalidInput
		}
		if port := parsed.Port(); port != "" {
			number, err := strconv.Atoi(port)
			if err != nil || number < 1 || number > 65_535 || strconv.Itoa(number) != port {
				return nil, ErrInvalidInput
			}
		}
		origin := parsed.Scheme + "://" + parsed.Host
		if !slices.Contains(result, origin) {
			result = append(result, origin)
		}
	}
	slices.Sort(result)
	return result, nil
}

func normalizeTrustedProxyCIDRs(values []string) ([]string, error) {
	if len(values) > maxTrustedProxyCIDRs {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if !strings.Contains(value, "/") {
			address, err := netip.ParseAddr(value)
			if err != nil {
				return nil, ErrInvalidInput
			}
			value = netip.PrefixFrom(address, address.BitLen()).String()
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
			// 0.0.0.0/0 or ::/0 would trust every client's own header.
			return nil, ErrInvalidInput
		}
		canonical := prefix.Masked().String()
		if !slices.Contains(result, canonical) {
			result = append(result, canonical)
		}
	}
	slices.Sort(result)
	return result, nil
}

// originForwardingChanges are the audit changes of the forwarding settings
// (the CA bundle by digest, never its text).
func originForwardingChanges(before, after OriginPool) []audit.Change {
	summary := func(pool OriginPool) map[string]any {
		websocket := OriginWebSocket{Enabled: true}
		if pool.WebSocket != nil {
			websocket = *pool.WebSocket
		}
		sticky := ""
		if pool.Sticky != nil {
			sticky = pool.Sticky.Source + ":" + pool.Sticky.Name
		}
		ca := ""
		if pool.TLS.CAPEM != "" {
			digest := sha256.Sum256([]byte(pool.TLS.CAPEM))
			ca = "sha256:" + hex.EncodeToString(digest[:])
		}
		backups, limited, inherited := 0, 0, 0
		for _, origin := range pool.Origins {
			if origin.Level > 0 {
				backups++
			}
			if origin.MaxConns != 0 {
				limited++
			}
			if origin.PortInherited {
				inherited++
			}
		}
		return map[string]any{
			"balance_method": pool.BalanceMethod, "hash_key": pool.HashKey, "sticky": sticky,
			"request_host": strings.TrimSuffix(pool.RequestHost.Mode+":"+pool.RequestHost.Value, ":"),
			"scheme":       pool.Scheme, "http_port": pool.HTTPPort, "https_port": pool.HTTPSPort, "tls_sni": pool.TLS.SNI, "tls_trust": pool.TLS.Trust,
			"tls_ca": ca, "follow_port": pool.FollowPort,
			"websocket_enabled": websocket.Enabled, "websocket_allowed_origins": strings.Join(websocket.AllowedOrigins, ","),
			"trusted_proxy_cidrs":  strings.Join(pool.TrustedProxyCIDRs, ","),
			"search_engine_origin": pool.SearchEngineOrigin, "acme_passthrough": pool.ACMEPassthrough,
			"response_buffering": boolValue(pool.ResponseBuffering, true), "request_buffering": boolValue(pool.RequestBuffering, true),
			"l2":             strings.TrimSuffix(pool.L2Mode+":"+uuidText(pool.L2ConfigID), ":"),
			"backup_origins": backups, "max_conns_origins": limited, "port_inherited_origins": inherited,
			"origin_auth_enabled": boolValue(pool.OriginAuthEnabled, true),
			"failback_mode":       pool.FailbackMode, "health_check_path": pool.HealthCheckPath,
			"follow_redirect": followRedirectSummary(pool.FollowRedirect),
		}
	}
	from, to := summary(before), summary(after)
	keys := make([]string, 0, len(to))
	for key := range to {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var changes []audit.Change
	for _, key := range keys {
		if from[key] != to[key] {
			changes = append(changes, audit.Change{Field: key, Before: from[key], After: to[key]})
		}
	}
	return changes
}

// followRedirectSummary: "off", or "on:<hops>[:cross_origin]" (audit).
func followRedirectSummary(redirect *OriginFollowRedirect) string {
	if redirect == nil || !redirect.Enabled {
		return "off"
	}
	value := "on:" + strconv.Itoa(redirect.MaxHops)
	if redirect.CrossOrigin {
		value += ":cross_origin"
	}
	return value
}

// normalizeSiteEdgeOptions validates and canonicalizes the site edit options
// (site-backend6): the search engine origin as basic.origins, buffering
// defaulted on, the L2 mode defaulted to the package's.
func normalizeSiteEdgeOptions(pool *OriginPool) error {
	if strings.TrimSpace(pool.SearchEngineOrigin) != "" {
		value, _, err := normalizeOrigin(pool.SearchEngineOrigin)
		if err != nil {
			return ErrInvalidInput
		}
		pool.SearchEngineOrigin = value
	} else {
		pool.SearchEngineOrigin = ""
	}
	on := true
	if pool.ResponseBuffering == nil {
		pool.ResponseBuffering = &on
	}
	if pool.RequestBuffering == nil {
		pool.RequestBuffering = &on
	}
	switch pool.L2Mode {
	case "":
		pool.L2Mode = SiteL2Package
		fallthrough
	case SiteL2Package, SiteL2Off:
		if pool.L2ConfigID != nil {
			return ErrInvalidInput
		}
	case SiteL2Custom:
		if pool.L2ConfigID == nil || *pool.L2ConfigID == uuid.Nil {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func uuidText(value *uuid.UUID) string {
	if value == nil {
		return ""
	}
	return value.String()
}
