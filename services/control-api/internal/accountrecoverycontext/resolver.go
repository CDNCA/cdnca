package accountrecoverycontext

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoveryhttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	defaultMaxProxyHops = 16
	maximumProxyHops    = 64
)

var (
	ErrInvalidConfig = errors.New("invalid account recovery context configuration")
	ErrUnavailable   = errors.New("account recovery context unavailable")

	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	traceIDPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

const resolveBindingSQL = `SELECT count(*)::bigint,
       COALESCE(min(binding.tenant_id::text), ''),
       COALESCE(min(binding.tenant_scope_id::text), ''),
       COALESCE(min(binding.hostname), '')
FROM account_recovery_public_hosts binding
JOIN access_scopes scope
  ON scope.id = binding.tenant_scope_id
 AND scope.tenant_id = binding.tenant_id
 AND scope.kind = 'tenant'
JOIN tenants tenant
  ON tenant.id = binding.tenant_id
 AND tenant.status = 'active'
WHERE binding.hostname = $1
  AND binding.state = 'active'`

const resolvePlatformSQL = `SELECT count(DISTINCT scope.id)::bigint,
       '',
       COALESCE(min(scope.id::text), ''),
       $1::text
FROM access_scopes scope
JOIN memberships membership
  ON membership.scope_id = scope.id
 AND membership.status = 'active'
JOIN users account
  ON account.id = membership.user_id
 AND account.status = 'active'
JOIN role_assignments assignment
  ON assignment.scope_id = scope.id
 AND assignment.user_id = account.id
JOIN roles role
  ON role.scope_id = scope.id
 AND role.id = assignment.role_id
 AND role.system_role
 AND role.name = 'platform_owner'
WHERE scope.kind = 'platform'
  AND scope.tenant_id IS NULL`

type QueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Metadata struct {
	RequestID string
	TraceID   string
}

type MetadataSource interface {
	Metadata(*http.Request) (Metadata, error)
}

type MetadataSourceFunc func(*http.Request) (Metadata, error)

func (function MetadataSourceFunc) Metadata(request *http.Request) (Metadata, error) {
	if function == nil {
		return Metadata{}, ErrUnavailable
	}
	return function(request)
}

type Config struct {
	TrustedProxyCIDRs    []string
	PlatformHosts        []string
	AllowPrivateSourceIP bool
	MaxProxyHops         int
	MetadataSource       MetadataSource
}

type Resolver struct {
	database             QueryRower
	trustedProxies       []netip.Prefix
	platformHosts        map[string]struct{}
	allowPrivateSourceIP bool
	maxProxyHops         int
	metadataSource       MetadataSource
}

func NewResolver(database QueryRower, config Config) (*Resolver, error) {
	if database == nil || config.MaxProxyHops < 0 || config.MaxProxyHops > maximumProxyHops {
		return nil, ErrInvalidConfig
	}
	if config.MaxProxyHops == 0 {
		config.MaxProxyHops = defaultMaxProxyHops
	}
	trustedProxies := make([]netip.Prefix, 0, len(config.TrustedProxyCIDRs))
	seen := make(map[netip.Prefix]struct{}, len(config.TrustedProxyCIDRs))
	for _, raw := range config.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.String() != raw || prefix.Bits() == 0 ||
			prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Addr().Unmap() {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, ErrInvalidConfig
		}
		seen[prefix] = struct{}{}
		trustedProxies = append(trustedProxies, prefix)
	}
	platformHosts := make(map[string]struct{}, len(config.PlatformHosts))
	for _, host := range config.PlatformHosts {
		address, addressErr := netip.ParseAddr(host)
		validAddress := addressErr == nil && address.Zone() == "" && address == address.Unmap() &&
			address.String() == host && !address.IsUnspecified()
		if !validAddress && !validPublicHostname(host) {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := platformHosts[host]; duplicate {
			return nil, ErrInvalidConfig
		}
		platformHosts[host] = struct{}{}
	}
	return &Resolver{
		database: database, trustedProxies: trustedProxies, platformHosts: platformHosts,
		allowPrivateSourceIP: config.AllowPrivateSourceIP,
		maxProxyHops:         config.MaxProxyHops, metadataSource: config.MetadataSource,
	}, nil
}

func (resolver *Resolver) Resolve(request *http.Request) (accountrecoveryhttp.TrustedContext, error) {
	if resolver == nil || request == nil {
		return accountrecoveryhttp.TrustedContext{}, ErrUnavailable
	}
	metadata, err := resolver.metadata(request)
	if err != nil {
		return accountrecoveryhttp.TrustedContext{}, ErrUnavailable
	}
	trusted := accountrecoveryhttp.TrustedContext{
		RequestID: metadata.RequestID,
		TraceID:   metadata.TraceID,
	}

	peer, err := remotePeer(request.RemoteAddr)
	if err != nil {
		return trusted, ErrUnavailable
	}
	hostname := request.Host
	source := peer
	if resolver.isTrustedProxy(peer) {
		hostname, source, err = resolver.trustedProxyContext(request, hostname)
		if err != nil {
			return trusted, ErrUnavailable
		}
	} else if disallowedSource(source, resolver.allowPrivateSourceIP) {
		return trusted, ErrUnavailable
	}
	trusted.SourceIP = source.String()
	if _, platform := resolver.platformHosts[hostname]; platform {
		return resolver.resolvePlatform(request.Context(), hostname, trusted)
	}
	if !validPublicHostname(hostname) {
		return trusted, ErrUnavailable
	}

	var count int64
	var tenantText, scopeText, storedHostname string
	if err := resolver.database.QueryRow(request.Context(), resolveBindingSQL, hostname).Scan(
		&count, &tenantText, &scopeText, &storedHostname,
	); err != nil {
		return trusted, ErrUnavailable
	}
	tenantID, tenantOK := canonicalUUID(tenantText)
	scopeID, scopeOK := canonicalUUID(scopeText)
	if count != 1 || !tenantOK || !scopeOK || storedHostname != hostname ||
		!validPublicHostname(storedHostname) {
		return trusted, ErrUnavailable
	}
	trusted.TenantID = tenantID
	trusted.ScopeID = scopeID
	return trusted, nil
}

func (resolver *Resolver) resolvePlatform(
	ctx context.Context,
	hostname string,
	trusted accountrecoveryhttp.TrustedContext,
) (accountrecoveryhttp.TrustedContext, error) {
	var count int64
	var tenantText, scopeText, storedHostname string
	if err := resolver.database.QueryRow(ctx, resolvePlatformSQL, hostname).Scan(
		&count, &tenantText, &scopeText, &storedHostname,
	); err != nil {
		return trusted, ErrUnavailable
	}
	scopeID, scopeOK := canonicalUUID(scopeText)
	if count != 1 || tenantText != "" || !scopeOK || storedHostname != hostname {
		return trusted, ErrUnavailable
	}
	trusted.ScopeID = scopeID
	return trusted, nil
}

func (resolver *Resolver) metadata(request *http.Request) (Metadata, error) {
	if resolver.metadataSource != nil {
		metadata, err := resolver.metadataSource.Metadata(request)
		if err != nil || !validMetadata(metadata) {
			return Metadata{}, ErrUnavailable
		}
		return metadata, nil
	}
	requestID, err := uuid.NewV7()
	if err != nil {
		return Metadata{}, ErrUnavailable
	}
	trace := make([]byte, 16)
	if _, err := rand.Read(trace); err != nil {
		return Metadata{}, ErrUnavailable
	}
	return Metadata{RequestID: requestID.String(), TraceID: hex.EncodeToString(trace)}, nil
}

func validMetadata(metadata Metadata) bool {
	return requestIDPattern.MatchString(metadata.RequestID) && traceIDPattern.MatchString(metadata.TraceID) &&
		metadata.TraceID != strings.Repeat("0", 32)
}

func (resolver *Resolver) trustedProxyContext(
	request *http.Request,
	requestHost string,
) (string, netip.Addr, error) {
	forwardedRaw, forwardedPresent, err := singleHeader(request, "Forwarded")
	if err != nil {
		return "", netip.Addr{}, err
	}
	xffRaw, xffPresent, err := singleHeader(request, "X-Forwarded-For")
	if err != nil {
		return "", netip.Addr{}, err
	}
	xfhRaw, xfhPresent, err := singleHeader(request, "X-Forwarded-Host")
	if err != nil {
		return "", netip.Addr{}, err
	}

	var forwarded forwardedValues
	if forwardedPresent {
		forwarded, err = parseForwarded(forwardedRaw, resolver.maxProxyHops)
		if err != nil {
			return "", netip.Addr{}, err
		}
	}
	if forwarded.hasFor && xffPresent {
		return "", netip.Addr{}, ErrUnavailable
	}
	if forwarded.host != "" && xfhPresent {
		return "", netip.Addr{}, ErrUnavailable
	}

	hostname := requestHost
	if forwarded.host != "" {
		hostname = forwarded.host
	} else if xfhPresent {
		hostname = xfhRaw
	}
	if _, platform := resolver.platformHosts[hostname]; !platform && !validPublicHostname(hostname) {
		return "", netip.Addr{}, ErrUnavailable
	}

	var chain []netip.Addr
	if forwarded.hasFor {
		chain = forwarded.forChain
	} else if xffPresent {
		chain, err = parseXForwardedFor(xffRaw, resolver.maxProxyHops)
		if err != nil {
			return "", netip.Addr{}, err
		}
	} else {
		return "", netip.Addr{}, ErrUnavailable
	}
	for index := len(chain) - 1; index >= 0; index-- {
		candidate := chain[index]
		if resolver.isTrustedProxy(candidate) {
			continue
		}
		if disallowedSource(candidate, resolver.allowPrivateSourceIP) {
			return "", netip.Addr{}, ErrUnavailable
		}
		return hostname, candidate, nil
	}
	return "", netip.Addr{}, ErrUnavailable
}

func (resolver *Resolver) isTrustedProxy(address netip.Addr) bool {
	for _, prefix := range resolver.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func singleHeader(request *http.Request, name string) (string, bool, error) {
	values := request.Header.Values(name)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] ||
		strings.ContainsAny(values[0], "\r\n\x00") {
		return "", false, ErrUnavailable
	}
	return values[0], true, nil
}

func remotePeer(raw string) (netip.Addr, error) {
	addressPort, err := netip.ParseAddrPort(raw)
	if err != nil || addressPort.Addr().Zone() != "" {
		return netip.Addr{}, ErrUnavailable
	}
	address := addressPort.Addr().Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, ErrUnavailable
	}
	return address, nil
}

func canonicalUUID(raw string) (uuid.UUID, bool) {
	value, err := uuid.Parse(raw)
	return value, err == nil && value != uuid.Nil && value.String() == raw
}

func disallowedSource(address netip.Addr, allowPrivate bool) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() {
		return true
	}
	return address.IsPrivate() && !allowPrivate
}

func validPublicHostname(hostname string) bool {
	if len(hostname) < 3 || len(hostname) > 253 || hostname != strings.ToLower(hostname) ||
		!strings.Contains(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}
	for index := 0; index < len(hostname); index++ {
		if hostname[index] > 0x7f {
			return false
		}
	}
	labels := strings.Split(hostname, ".")
	allNumeric := true
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || !asciiAlphaNumeric(label[0]) ||
			!asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if !asciiAlphaNumeric(character) && character != '-' {
				return false
			}
			if character < '0' || character > '9' {
				allNumeric = false
			}
		}
	}
	if allNumeric {
		return false
	}
	for _, reserved := range []string{"localhost", "local", "internal"} {
		if hostname == reserved || strings.HasSuffix(hostname, "."+reserved) {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

type forwardedValues struct {
	forChain []netip.Addr
	host     string
	hasFor   bool
}

func parseForwarded(raw string, maxHops int) (forwardedValues, error) {
	elements, err := splitOutsideQuotes(raw, ',')
	if err != nil || len(elements) == 0 || len(elements) > maxHops {
		return forwardedValues{}, ErrUnavailable
	}
	result := forwardedValues{forChain: make([]netip.Addr, 0, len(elements))}
	for _, element := range elements {
		parameters, err := splitOutsideQuotes(element, ';')
		if err != nil || len(parameters) == 0 {
			return forwardedValues{}, ErrUnavailable
		}
		seen := make(map[string]struct{}, len(parameters))
		forSeen := false
		for _, parameter := range parameters {
			name, rawValue, ok := strings.Cut(parameter, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if !ok || name == "" || strings.TrimSpace(rawValue) != rawValue || !validToken(name) {
				return forwardedValues{}, ErrUnavailable
			}
			if _, duplicate := seen[name]; duplicate {
				return forwardedValues{}, ErrUnavailable
			}
			seen[name] = struct{}{}
			value, err := forwardedValue(rawValue)
			if err != nil {
				return forwardedValues{}, ErrUnavailable
			}
			switch name {
			case "for":
				address, err := forwardedAddress(value, true)
				if err != nil {
					return forwardedValues{}, ErrUnavailable
				}
				result.forChain = append(result.forChain, address)
				result.hasFor = true
				forSeen = true
			case "host":
				if result.host != "" || !validPublicHostname(value) {
					return forwardedValues{}, ErrUnavailable
				}
				result.host = value
			}
		}
		if result.hasFor && !forSeen {
			return forwardedValues{}, ErrUnavailable
		}
	}
	if result.hasFor && len(result.forChain) != len(elements) {
		return forwardedValues{}, ErrUnavailable
	}
	return result, nil
}

func parseXForwardedFor(raw string, maxHops int) ([]netip.Addr, error) {
	parts := strings.Split(raw, ",")
	if len(parts) == 0 || len(parts) > maxHops {
		return nil, ErrUnavailable
	}
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" || strings.ContainsAny(value, "\"\\;\r\n\x00") {
			return nil, ErrUnavailable
		}
		address, err := forwardedAddress(value, false)
		if err != nil {
			return nil, ErrUnavailable
		}
		chain = append(chain, address)
	}
	return chain, nil
}

func forwardedAddress(raw string, bracketIPv6 bool) (netip.Addr, error) {
	lower := strings.ToLower(raw)
	if lower == "unknown" || strings.HasPrefix(raw, "_") {
		return netip.Addr{}, ErrUnavailable
	}
	if strings.HasPrefix(raw, "[") {
		if !strings.HasSuffix(raw, "]") || strings.Count(raw, "[") != 1 || strings.Count(raw, "]") != 1 {
			return netip.Addr{}, ErrUnavailable
		}
		raw = raw[1 : len(raw)-1]
	} else if bracketIPv6 && strings.Contains(raw, ":") {
		return netip.Addr{}, ErrUnavailable
	}
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, ErrUnavailable
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, ErrUnavailable
	}
	return address, nil
}

func splitOutsideQuotes(raw string, separator byte) ([]string, error) {
	var result []string
	start := 0
	quoted := false
	escaped := false
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if character < 0x20 || character == 0x7f {
			return nil, ErrUnavailable
		}
		if escaped {
			escaped = false
			continue
		}
		if quoted && character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			quoted = !quoted
			continue
		}
		if character == separator && !quoted {
			part := strings.TrimSpace(raw[start:index])
			if part == "" {
				return nil, ErrUnavailable
			}
			result = append(result, part)
			start = index + 1
		}
	}
	if quoted || escaped {
		return nil, ErrUnavailable
	}
	part := strings.TrimSpace(raw[start:])
	if part == "" {
		return nil, ErrUnavailable
	}
	return append(result, part), nil
}

func forwardedValue(raw string) (string, error) {
	if raw == "" {
		return "", ErrUnavailable
	}
	if raw[0] != '"' {
		if !validToken(raw) {
			return "", ErrUnavailable
		}
		return raw, nil
	}
	if len(raw) < 2 || raw[len(raw)-1] != '"' {
		return "", ErrUnavailable
	}
	buffer := make([]byte, 0, len(raw)-2)
	for index := 1; index < len(raw)-1; index++ {
		character := raw[index]
		if character == '\\' {
			index++
			if index >= len(raw)-1 || raw[index] != '\\' && raw[index] != '"' {
				return "", ErrUnavailable
			}
			character = raw[index]
		}
		if character < 0x20 || character == 0x7f || character == '"' {
			return "", ErrUnavailable
		}
		buffer = append(buffer, character)
	}
	if len(buffer) == 0 {
		return "", ErrUnavailable
	}
	return string(buffer), nil
}

func validToken(raw string) bool {
	if raw == "" {
		return false
	}
	for index := 0; index < len(raw); index++ {
		character := raw[index]
		if asciiAlphaNumeric(character) || character >= 'A' && character <= 'Z' {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}
