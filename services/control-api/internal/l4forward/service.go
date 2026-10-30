package l4forward

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var geoRegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return WriteResult{}, err
	}
	groupIDs, err := normalizeGroupIDs(request.GroupIDs)
	if err != nil {
		return WriteResult{}, err
	}
	request.GroupIDs = groupIDs
	// 「默认设置」按生效范围带入监听协议/负载方式等；显式提交的值仍然优先。
	defaults, err := s.resolveFieldDefaults(ctx, actor, request.TargetScopeID, request.OwnerUserID, groupIDs)
	if err != nil {
		return WriteResult{}, err
	}
	applyFieldDefaults(&request.Fields, defaults)
	if err := normalizeFields(&request.Fields); err != nil || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, locatedOrInvalid(err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID   `json:"target_scope_id"`
		OwnerUserID   uuid.UUID   `json:"owner_user_id"`
		Fields        Fields      `json:"fields"`
		GroupIDs      []uuid.UUID `json:"group_ids"`
	}{request.TargetScopeID, request.OwnerUserID, request.Fields, request.GroupIDs})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.Create(ctx, actor, request, id, digest)
	redact(&result.Forward, actor.ScopeKind)
	return result, err
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if request.GroupIDs != nil {
		groupIDs, err := normalizeGroupIDs(*request.GroupIDs)
		if err != nil {
			return WriteResult{}, err
		}
		request.GroupIDs = &groupIDs
	}
	if err := normalizeFields(&request.Fields); err != nil {
		return WriteResult{}, locatedOrInvalid(err)
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID    `json:"id"`
		ExpectedRevision int64        `json:"expected_revision"`
		Fields           Fields       `json:"fields"`
		GroupIDs         *[]uuid.UUID `json:"group_ids"`
	}{request.ID, request.ExpectedRevision, request.Fields, request.GroupIDs})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.Update(ctx, actor, request, digest)
	redact(&result.Forward, actor.ScopeKind)
	return result, err
}

func (s *Service) Delete(ctx context.Context, actor Actor, request DeleteRequest) (DeleteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return DeleteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.ID, request.ExpectedRevision})
	if err != nil {
		return DeleteResult{}, err
	}
	return s.store.Delete(ctx, actor, request, digest)
}

func (s *Service) Get(ctx context.Context, actor Actor, id uuid.UUID) (Forward, error) {
	if !validActor(actor) || id == uuid.Nil {
		return Forward{}, ErrInvalidInput
	}
	item, err := s.store.Get(ctx, actor, id)
	redact(&item, actor.ScopeKind)
	return item, err
}

func (s *Service) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	filter.Search = strings.TrimSpace(filter.Search)
	if !validActor(actor) || filter.Page < 1 || filter.Page > 1_000_000 || filter.Limit < 1 || filter.Limit > 100 ||
		utf8.RuneCountInString(filter.Search) > 128 || (filter.Protocol != "" && filter.Protocol != ProtocolTCP && filter.Protocol != ProtocolUDP) ||
		(filter.ListenPort != nil && (*filter.ListenPort < 1 || *filter.ListenPort > 65535)) ||
		(filter.DisplayID != nil && *filter.DisplayID < 1) ||
		(filter.OwnerDisplayID != nil && *filter.OwnerDisplayID < 1) ||
		(filter.PublicationState != "" && !ValidPublicationState(filter.PublicationState)) ||
		(filter.GroupID != nil && *filter.GroupID == uuid.Nil) ||
		(filter.PackageProductID != nil && *filter.PackageProductID == uuid.Nil) ||
		(filter.Upstream != "" && !validDisplayText(filter.Upstream, 253, false)) ||
		(filter.CNAMEDomain != "" && !validDisplayText(filter.CNAMEDomain, 253, false)) ||
		(filter.CNAMEHostname != "" && !validDisplayText(filter.CNAMEHostname, 253, false)) ||
		(filter.RegionID != nil && *filter.RegionID == uuid.Nil) || (filter.NodeGroupID != nil && *filter.NodeGroupID == uuid.Nil) ||
		(filter.SyncState != "" && filter.SyncState != SyncStateDone && filter.SyncState != SyncStatePending && filter.SyncState != SyncStateFailed) ||
		(filter.AdminStatus != "" && !ValidAdminStatus(filter.AdminStatus)) {
		return ListResult{}, ErrInvalidInput
	}
	// 区域 / 线路分组 are the platform's (shown to the admin only).
	if actor.ScopeKind == "tenant" && (filter.RegionID != nil || filter.NodeGroupID != nil) {
		return ListResult{}, ErrPermissionDenied
	}
	filter.Upstream = strings.ToLower(strings.TrimSpace(filter.Upstream))
	filter.CNAMEDomain = strings.ToLower(strings.TrimSpace(filter.CNAMEDomain))
	filter.CNAMEHostname = strings.ToLower(strings.TrimSpace(filter.CNAMEHostname))
	result, err := s.store.List(ctx, actor, filter)
	if actor.ScopeKind == "tenant" {
		for index := range result.Items {
			redact(&result.Items[index], actor.ScopeKind)
		}
	}
	return result, err
}

func ValidAdminStatus(value string) bool {
	switch value {
	case AdminStatusNormal, AdminStatusLocked, AdminStatusTrafficExceeded, AdminStatusPackageExpired:
		return true
	}
	return false
}

func ValidPublicationState(value string) bool {
	switch value {
	case PublicationStateUnknown, PublicationStatePending, PublicationStateLeased, PublicationStateRetrying,
		PublicationStateReconciling, PublicationStateSucceeded, PublicationStateFailed, PublicationStateSuperseded:
		return true
	default:
		return false
	}
}

// locatedOrInvalid keeps a located port conflict (a node port or the
// forward's own sockets, PortConflictError) and reports any other field error
// as invalid input.
func locatedOrInvalid(err error) error {
	var located *PortConflictError
	if errors.As(err, &located) {
		return located
	}
	var field *FieldError
	if errors.As(err, &field) {
		return field
	}
	return ErrInvalidInput
}

func normalizeActorAndTarget(actor Actor, targetScopeID, ownerUserID *uuid.UUID) error {
	if !validActor(actor) {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "platform" {
		if *targetScopeID == uuid.Nil || *ownerUserID == uuid.Nil {
			return ErrInvalidInput
		}
		return nil
	}
	if (*targetScopeID != uuid.Nil && *targetScopeID != actor.ScopeID) ||
		(*ownerUserID != uuid.Nil && *ownerUserID != actor.UserID) {
		return ErrPermissionDenied
	}
	*targetScopeID = actor.ScopeID
	*ownerUserID = actor.UserID
	return nil
}

func normalizeFields(fields *Fields) error {
	if !validDisplayText(fields.Name, 128, false) {
		return fieldError("name", "invalid")
	}
	if !validDisplayText(fields.Remark, 256, true) {
		return fieldError("remark", "invalid")
	}
	fields.Name = strings.TrimSpace(fields.Name)
	fields.Remark = strings.TrimSpace(fields.Remark)
	if err := normalizeOrigins(fields); err != nil {
		return fieldError("origins", "invalid")
	}
	if fields.UpstreamFollowPort && fields.UpstreamPort == 0 {
		fields.UpstreamPort = fields.ListenPort // follow-port stores the listen port
	}
	// Community edition: a forward needs no package (nil: the forward's own
	// line group, else the platform default one).
	if fields.PackageSubscriptionID != nil && *fields.PackageSubscriptionID == uuid.Nil {
		fields.PackageSubscriptionID = nil
	}
	if utf8.RuneCountInString(fields.Name) < 1 || utf8.RuneCountInString(fields.Name) > 128 ||
		(fields.Protocol != ProtocolTCP && fields.Protocol != ProtocolUDP) || fields.ListenAddress != "*" ||
		fields.ListenPort == 0 || fields.UpstreamPort == 0 ||
		fields.ConnectTimeoutMS < 50 || fields.ConnectTimeoutMS > 30000 ||
		fields.ResponseTimeoutMS < 100 || fields.ResponseTimeoutMS > 600000 ||
		fields.MaxConnectionsPerClient < 1 || fields.MaxConnectionsPerClient > 10000 ||
		!validNewConnectionRate(fields) {
		return ErrInvalidInput
	}
	// L4-006: combinations name the field and the reason
	switch {
	case fields.Protocol == ProtocolUDP && fields.ProxyProtocolInbound:
		return fieldError("proxy_protocol_inbound", "udp_unsupported")
	case fields.Protocol == ProtocolUDP && fields.ProxyProtocolV1:
		return fieldError("proxy_protocol_v1", "udp_unsupported")
	case fields.TOA && fields.Protocol != ProtocolTCP:
		return fieldError("toa", "tcp_only")
	case fields.TOA && (fields.ProxyProtocolInbound || fields.ProxyProtocolV1):
		return fieldError("toa", "proxy_protocol_conflict")
	}
	if err := normalizeUpstream(fields); err != nil {
		return err
	}
	if err := normalizeGeoPolicy(&fields.Geo); err != nil {
		return fieldError("geo_policy", "invalid")
	}
	trustedProxySource := fields.Geo.Enabled && len(fields.Geo.TrustedProxyCIDRs) > 0
	if fields.ProxyProtocolInbound && !trustedProxySource {
		// 接收入站 PROXY 时地区识别要用 PROXY 头里的客户端地址，须配可信代理来源
		return fieldError("proxy_protocol_inbound", "trusted_proxy_required")
	}
	if !fields.ProxyProtocolInbound && trustedProxySource {
		return fieldError("proxy_protocol_inbound", "required_by_trusted_proxy")
	}
	// 负载方式对应转发列表的「线路」列，未指定时按轮询落库。
	if fields.BalanceWay == "" {
		fields.BalanceWay = BalanceWayRoundRobin
	}
	if fields.BalanceWay != BalanceWayRoundRobin && fields.BalanceWay != BalanceWayIPHash {
		return fieldError("balance_way", "invalid")
	}
	if err := normalizeAdditionalListeners(fields); err != nil {
		return err
	}
	if err := normalizeTLSPassthrough(fields); err != nil {
		return err
	}
	if err := normalizeGuardRules(fields); err != nil {
		return fieldError("guard_rules", "invalid")
	}
	if err := normalizeACL(fields); err != nil {
		return fieldError("acl", "invalid")
	}
	if len(fields.Origins) > 1 && fields.UpstreamFollowPort {
		return fieldError("upstream_follow_port", "origins_conflict") // several origins share one origin port
	}
	return normalizePortRanges(fields)
}

// normalizeOrigins checks a 源站列表 and takes upstream_address/upstream_host
// from its first origin. One origin may be an IP address or a domain (then
// the stream's DNS policy applies); several are IP addresses (edgeconfig
// L4OriginsMax, unique, weight 1..100, at least one up). A single up origin
// of weight 1 is stored as no list (the plain single-origin stream).
func normalizeOrigins(fields *Fields) error {
	if fields.Origins == nil {
		return nil
	}
	if len(fields.Origins) == 0 || len(fields.Origins) > edgeconfig.L4OriginsMax {
		return ErrInvalidInput
	}
	if len(fields.Origins) == 1 {
		origin := fields.Origins[0]
		if origin.Weight < 1 || origin.Weight > edgeconfig.L4OriginWeightMax || origin.Down {
			return ErrInvalidInput
		}
		address := strings.TrimSpace(origin.Address)
		if _, err := netip.ParseAddr(address); err == nil {
			fields.UpstreamAddress, fields.UpstreamHost = address, ""
		} else {
			fields.UpstreamAddress, fields.UpstreamHost = "", address
		}
		fields.Origins = nil
		return nil
	}
	origins := make([]edgeconfig.L4OriginV2, len(fields.Origins))
	for index, origin := range fields.Origins {
		origins[index] = edgeconfig.L4OriginV2{Address: strings.TrimSpace(origin.Address), Weight: origin.Weight, Down: origin.Down}
	}
	normalized, err := edgeconfig.NormalizeL4Origins(origins)
	if err != nil || fields.DNS != (DNSPolicy{}) {
		return ErrInvalidInput
	}
	fields.Origins = make([]Origin, len(normalized))
	for index, origin := range normalized {
		fields.Origins[index] = Origin{Address: origin.Address, Weight: origin.Weight, Down: origin.Down}
	}
	fields.UpstreamAddress, fields.UpstreamHost = normalized[0].Address, ""
	return nil
}

// ACLRulesMax bounds a stream's IP 访问规则 (with the default deny rule they
// still fit edgeconfig.L4GuardCIDRsMax next to other guard CIDRs).
const ACLRulesMax = 1024

// normalizeACL canonicalizes the 访问控制 IP rules: networks masked, single
// addresses as /32 or /128, order kept, duplicates refused. Default allow
// without rules is stored as no ACL (nil).
func normalizeACL(fields *Fields) error {
	if fields.ACL == nil {
		return nil
	}
	acl := fields.ACL
	if acl.DefaultAction == "" {
		acl.DefaultAction = ACLActionAllow
	}
	if (acl.DefaultAction != ACLActionAllow && acl.DefaultAction != ACLActionDeny) || len(acl.Rules) > ACLRulesMax {
		return ErrInvalidInput
	}
	rules := make([]ACLRule, 0, len(acl.Rules))
	seen := make(map[string]struct{}, len(acl.Rules))
	for _, rule := range acl.Rules {
		cidr, err := canonicalACLNetwork(rule.CIDR)
		if err != nil || (rule.Action != ACLActionAllow && rule.Action != ACLActionDeny) {
			return ErrInvalidInput
		}
		if _, duplicate := seen[cidr]; duplicate {
			return ErrInvalidInput
		}
		seen[cidr] = struct{}{}
		rules = append(rules, ACLRule{CIDR: cidr, Action: rule.Action})
	}
	if acl.DefaultAction == ACLActionAllow && len(rules) == 0 {
		fields.ACL = nil
		return nil
	}
	fields.ACL = &ACL{DefaultAction: acl.DefaultAction, Rules: rules}
	return nil
}

// canonicalACLNetwork accepts "1.2.3.4", "1.2.3.0/24" or an IPv6 form.
func canonicalACLNetwork(value string) (string, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" || address.Is4In6() {
			return "", ErrInvalidInput
		}
		return netip.PrefixFrom(address, address.BitLen()).String(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return "", ErrInvalidInput
	}
	return prefix.Masked().String(), nil
}

// normalizeGuardRules checks the guard rules as the edge does
// (edgeconfig.NormalizeL4GuardRules: server_names only on TLS passthrough).
func normalizeGuardRules(fields *Fields) error {
	rules, err := edgeconfig.NormalizeL4GuardRules(fields.GuardRules, fields.TLSPassthrough)
	if err != nil {
		return ErrInvalidInput
	}
	fields.GuardRules = rules
	return nil
}

// validNewConnectionRate: 0 is unlimited and then takes no burst or ban; a
// rate is bounded as edgeconfig.ValidL4NewConnRate (migration 299).
func validNewConnectionRate(fields *Fields) bool {
	if fields.MaxNewConnectionsPerClientPerSecond == 0 {
		return fields.NewConnectionBurst == 0 && fields.NewConnectionBanSeconds == 0
	}
	return edgeconfig.ValidL4NewConnRate(newConnRate(fields.MaxNewConnectionsPerClientPerSecond,
		fields.NewConnectionBurst, fields.NewConnectionBanSeconds))
}

// newConnRate is the edge contract of a stream's rate, nil when unlimited.
func newConnRate(rate, burst, banSeconds int) *edgeconfig.L4NewConnRateV2 {
	if rate == 0 {
		return nil
	}
	return &edgeconfig.L4NewConnRateV2{RatePerSecond: rate, Burst: burst, BanSeconds: banSeconds}
}

func validDisplayText(value string, maxRunes int, emptyAllowed bool) bool {
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	length := utf8.RuneCountInString(strings.TrimSpace(value))
	return length <= maxRunes && (emptyAllowed || length > 0)
}

func normalizeUpstream(fields *Fields) error {
	addressInput := strings.TrimSpace(fields.UpstreamAddress)
	hostInput := fields.UpstreamHost
	if (addressInput == "") == (hostInput == "") {
		return fieldError("upstream_address", "required")
	}
	if addressInput != "" {
		address, err := netip.ParseAddr(addressInput)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
			return fieldError("upstream_address", "invalid")
		}
		if fields.DNS != (DNSPolicy{}) {
			return fieldError("dns_policy", "invalid")
		}
		fields.UpstreamAddress = address.String()
		fields.UpstreamHost = ""
		return nil
	}

	host, err := canonicalUpstreamHost(hostInput)
	if err != nil {
		return fieldError("upstream_host", "invalid")
	}
	if normalizeDNSPolicy(&fields.DNS) != nil {
		return fieldError("dns_policy", "invalid")
	}
	fields.UpstreamAddress = ""
	fields.UpstreamHost = host
	return nil
}

func canonicalUpstreamHost(value string) (string, error) {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", ErrInvalidInput
	}
	value = strings.TrimSuffix(value, ".")
	host, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", ErrInvalidInput
	}
	host = strings.ToLower(host)
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".in-addr.arpa") || strings.HasSuffix(host, ".ip6.arpa") {
		return "", ErrInvalidInput
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", ErrInvalidInput
	}
	return host, nil
}

func normalizeDNSPolicy(policy *DNSPolicy) error {
	if policy.PositiveMinTTLSeconds < 1 || policy.PositiveMinTTLSeconds > 300 ||
		policy.PositiveMaxTTLSeconds < policy.PositiveMinTTLSeconds || policy.PositiveMaxTTLSeconds > 86400 ||
		policy.NegativeTTLSeconds < 1 || policy.NegativeTTLSeconds > 3600 ||
		policy.StaleIfErrorSeconds < policy.PositiveMaxTTLSeconds || policy.StaleIfErrorSeconds > 86400 ||
		policy.AllowPrivateAddresses {
		return ErrInvalidInput
	}
	return nil
}

func normalizeGeoPolicy(policy *GeoPolicy) error {
	if !policy.Enabled {
		if (policy.UnknownRegionAction != "" && policy.UnknownRegionAction != GeoActionAllow) || len(policy.TrustedProxyCIDRs) != 0 ||
			len(policy.BlockedRegions) != 0 || len(policy.RegionCIDRs) != 0 {
			return ErrInvalidInput
		}
		policy.UnknownRegionAction = GeoActionAllow
		policy.TrustedProxyCIDRs = []string{}
		policy.BlockedRegions = []string{}
		policy.RegionCIDRs = []GeoRegionCIDRs{}
		return nil
	}
	if policy.UnknownRegionAction != GeoActionAllow && policy.UnknownRegionAction != GeoActionBlock {
		return ErrInvalidInput
	}
	trusted, err := normalizePrefixes(policy.TrustedProxyCIDRs, 64, true)
	if err != nil {
		return err
	}
	regions, authority, err := normalizeRegionCIDRs(policy.RegionCIDRs)
	if err != nil {
		return err
	}
	blocked, err := normalizeRegions(policy.BlockedRegions, 256)
	if err != nil {
		return err
	}
	for _, region := range blocked {
		if _, ok := authority[region]; !ok {
			return ErrInvalidInput
		}
	}
	policy.TrustedProxyCIDRs = trusted
	policy.BlockedRegions = blocked
	policy.RegionCIDRs = regions
	return nil
}

func normalizeRegionCIDRs(input []GeoRegionCIDRs) ([]GeoRegionCIDRs, map[string]struct{}, error) {
	if len(input) == 0 || len(input) > 256 {
		return nil, nil, ErrInvalidInput
	}
	result := make([]GeoRegionCIDRs, 0, len(input))
	authority := make(map[string]struct{}, len(input))
	type ownedPrefix struct {
		region string
		prefix netip.Prefix
	}
	all := make([]ownedPrefix, 0)
	for _, entry := range input {
		regions, err := normalizeRegions([]string{entry.Region}, 1)
		if err != nil || len(entry.CIDRs) == 0 {
			return nil, nil, ErrInvalidInput
		}
		region := regions[0]
		if _, exists := authority[region]; exists {
			return nil, nil, ErrInvalidInput
		}
		cidrs, err := normalizePrefixes(entry.CIDRs, 4096, false)
		if err != nil {
			return nil, nil, err
		}
		for _, cidr := range cidrs {
			prefix := netip.MustParsePrefix(cidr)
			for _, prior := range all {
				if prior.prefix.Addr().BitLen() == prefix.Addr().BitLen() &&
					(prior.prefix.Contains(prefix.Addr()) || prefix.Contains(prior.prefix.Addr())) {
					return nil, nil, ErrInvalidInput
				}
			}
			all = append(all, ownedPrefix{region: region, prefix: prefix})
		}
		authority[region] = struct{}{}
		result = append(result, GeoRegionCIDRs{Region: region, CIDRs: cidrs})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Region < result[j].Region })
	return result, authority, nil
}

func normalizeRegions(input []string, maximum int) ([]string, error) {
	if len(input) > maximum {
		return nil, ErrInvalidInput
	}
	set := make(map[string]struct{}, len(input))
	for _, raw := range input {
		region := strings.ToLower(strings.TrimSpace(raw))
		if !geoRegionPattern.MatchString(region) {
			return nil, ErrInvalidInput
		}
		set[region] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for region := range set {
		result = append(result, region)
	}
	sort.Strings(result)
	return result, nil
}

func normalizePrefixes(input []string, maximum int, rejectUnspecified bool) ([]string, error) {
	if len(input) > maximum {
		return nil, ErrInvalidInput
	}
	set := make(map[string]struct{}, len(input))
	for _, raw := range input {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() ||
			(rejectUnspecified && prefix.Addr().IsUnspecified()) {
			return nil, ErrInvalidInput
		}
		set[prefix.Masked().String()] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for prefix := range set {
		result = append(result, prefix)
	}
	sort.Strings(result)
	return result, nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validWriteMetadata(key, requestID string) bool {
	return idempotencyPattern.MatchString(key) && idempotencyPattern.MatchString(requestID)
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func redact(item *Forward, scopeKind string) {
	if scopeKind == "tenant" {
		item.Owner = nil
	}
}
