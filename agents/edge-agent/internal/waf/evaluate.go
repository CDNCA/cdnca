package waf

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	reasonAllowlistContinue   = "allowlist_continue"
	reasonAllowlistStop       = "allowlist_stop"
	reasonBlock               = "rule_block"
	reasonLog                 = "rule_log"
	reasonNoMatch             = "no_match"
	reasonInvalidRequest      = "request_limit"
	reasonInvalidPolicy       = "invalid_policy"
	reasonExpiredRule         = "rule_expired"
	reasonClientSourceInvalid = "client_source_invalid"
	reasonCrawlerGeoBypass    = "crawler_geo_bypass"
	reasonUnknownGeoAllow     = "unknown_geo_allow"
	reasonUnknownGeoBlock     = "unknown_geo_block"
	maxRequestPathBytes       = 4096
	maxRequestValueBytes      = 4096
)

type Evaluator struct {
	highWaterUnix atomic.Int64
}

var defaultEvaluator Evaluator

func Evaluate(policy *CompiledPolicy, request Request) Decision {
	return defaultEvaluator.EvaluateAt(policy, request, time.Now())
}

func (evaluator *Evaluator) EvaluateAt(policy *CompiledPolicy, request Request, now time.Time) Decision {
	decision := Decision{Action: ActionAllow, Reason: reasonNoMatch}
	if policy == nil {
		return Decision{Action: ActionBlock, Reason: reasonInvalidRequest}
	}
	decision.Version = policy.PolicyVersion
	if !policy.valid {
		decision.Action = ActionBlock
		decision.Reason = reasonInvalidPolicy
		return decision
	}
	if !validRequest(request) {
		decision.Action = ActionBlock
		decision.Reason = reasonInvalidRequest
		return decision
	}
	request, ok := resolveClientSource(policy, request)
	if !ok {
		decision.Action = ActionBlock
		decision.Reason = reasonClientSourceInvalid
		return decision
	}
	effectiveNow, ok := evaluator.observe(now)
	if !ok {
		decision.Action = ActionBlock
		decision.Reason = reasonInvalidRequest
		return decision
	}

	country := countryFor(policy.Geo, request.SourceAddr)
	crawler := trustedCrawler(policy, request)
	if country == "" && policy.UnknownGeoAction != "" {
		if crawler {
			decision.Events = append(decision.Events, Event{Reason: reasonCrawlerGeoBypass})
		} else if policy.UnknownGeoAction == GeoUnknownBlock {
			decision.Action = ActionBlock
			decision.Reason = reasonUnknownGeoBlock
			decision.Events = append(decision.Events, Event{Reason: decision.Reason})
			return decision
		} else {
			decision.Reason = reasonUnknownGeoAllow
			decision.Events = append(decision.Events, Event{Reason: decision.Reason})
		}
	}
	for _, rule := range policy.Rules {
		if crawler && rule.Match.Country != nil && matchesWithoutCountry(rule.Match, request) &&
			countryMatches(*rule.Match.Country, country) {
			if expired(rule, effectiveNow) {
				decision.Events = append(decision.Events, Event{Reason: reasonExpiredRule, RuleID: rule.RuleID})
			} else {
				decision.Events = append(decision.Events, Event{Reason: reasonCrawlerGeoBypass, RuleID: rule.RuleID})
			}
			continue
		}
		if !matchesCountry(rule.Match, request, country) {
			continue
		}
		if expired(rule, effectiveNow) {
			decision.Events = append(decision.Events, Event{Reason: reasonExpiredRule, RuleID: rule.RuleID})
			continue
		}
		switch rule.Action {
		case ActionAllow:
			decision.Action = ActionAllow
			decision.Reason = reasonAllowlistContinue
			if rule.Flow == FlowStop {
				decision.Reason = reasonAllowlistStop
			}
		case ActionLog:
			decision.Action = ActionLog
			decision.Reason = reasonLog
		case ActionBlock:
			decision.Action = ActionBlock
			decision.Reason = reasonBlock
		}
		decision.RuleID = rule.RuleID
		decision.Events = append(decision.Events, Event{Reason: decision.Reason, RuleID: rule.RuleID})
		if rule.Flow == FlowStop {
			break
		}
	}
	return decision
}

func resolveClientSource(policy *CompiledPolicy, request Request) (Request, bool) {
	if policy.ClientSource == nil {
		return request, true
	}
	if !safeClientAddress(request.SourceAddr) {
		return request, false
	}
	forwarded, found, unambiguous := singleHeader(request.Header, policy.ClientSource.Header)
	peerTrusted := cidrListMatches(policy.ClientSource.TrustedProxyCIDRs, request.SourceAddr)
	if !peerTrusted {
		return request, !found
	}
	if !found || !unambiguous {
		return request, false
	}
	parts := strings.Split(forwarded, ",")
	if len(parts) == 0 || len(parts) > int(policy.ClientSource.MaxHops) {
		return request, false
	}
	chain := make([]netip.Addr, len(parts))
	for index, part := range parts {
		value := strings.TrimSpace(part)
		address, err := netip.ParseAddr(value)
		if err != nil || value == "" || !safeClientAddress(address) {
			return request, false
		}
		chain[index] = address
	}
	for index := len(chain) - 1; index >= 0; index-- {
		if cidrListMatches(policy.ClientSource.TrustedProxyCIDRs, chain[index]) {
			continue
		}
		request.SourceAddr = chain[index]
		return request, true
	}
	return request, false
}

func trustedCrawler(policy *CompiledPolicy, request Request) bool {
	if len(policy.TrustedCrawlers) == 0 {
		return false
	}
	userAgent, found, unambiguous := singleHeader(request.Header, "user-agent")
	if !found || !unambiguous {
		return false
	}
	for _, crawler := range policy.TrustedCrawlers {
		if !cidrListMatches(crawler.Networks, request.SourceAddr) {
			continue
		}
		for _, prefix := range crawler.UserAgentPrefixes {
			if strings.HasPrefix(userAgent, prefix) {
				return true
			}
		}
	}
	return false
}

func singleHeader(headers map[string][]string, name string) (string, bool, bool) {
	var values []string
	found := false
	for key, candidates := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		if found {
			return "", true, false
		}
		found = true
		values = candidates
	}
	if !found {
		return "", false, true
	}
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, true, len(values) == 1 && returnValue != ""
}

func cidrListMatches(cidrs []CompiledCIDR, address netip.Addr) bool {
	for _, cidr := range cidrs {
		if cidrMatches(cidr, address) {
			return true
		}
	}
	return false
}

func safeClientAddress(address netip.Addr) bool {
	return address.IsValid() && !address.Is4In6() && !address.IsUnspecified() && !address.IsMulticast() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast()
}

func matchesWithoutCountry(match CompiledMatch, request Request) bool {
	match.Country = nil
	return matchesCountry(match, request, "")
}

func (evaluator *Evaluator) observe(now time.Time) (int64, bool) {
	if evaluator == nil || now.IsZero() {
		return 0, false
	}
	observed := now.Unix()
	if observed <= 0 || observed > MaxPolicyVersion {
		return 0, false
	}
	for {
		current := evaluator.highWaterUnix.Load()
		if observed <= current {
			return current, true
		}
		if evaluator.highWaterUnix.CompareAndSwap(current, observed) {
			return observed, true
		}
	}
}

func expired(rule CompiledRule, effectiveNow int64) bool {
	return rule.ExpiresAtUnix != 0 && effectiveNow >= rule.ExpiresAtUnix
}

func validRequest(request Request) bool {
	if !request.SourceAddr.IsValid() || request.SourceAddr.Is4In6() || request.Port == 0 ||
		len(request.Host) > MaxHostBytes || len(request.Method) > MaxMethodBytes || len(request.Path) > maxRequestPathBytes {
		return false
	}
	if _, err := normalizeHost(request.Host); err != nil {
		return false
	}
	return isToken(request.Method) && len(request.Path) > 0 && request.Path[0] == '/' &&
		utf8.ValidString(request.Path) && !hasControl(request.Path) &&
		validRequestValues(request.Query, false) && validRequestValues(request.Header, true)
}

func validRequestValues(values map[string][]string, header bool) bool {
	fieldCount := 0
	for name, candidates := range values {
		if len(name) > MaxNameBytes || hasControl(name) || (header && !isToken(name)) {
			return false
		}
		fields := len(candidates)
		if fields == 0 {
			fields = 1
		}
		if fields > MaxRequestFields-fieldCount {
			return false
		}
		fieldCount += fields
		for _, value := range candidates {
			if len(value) > maxRequestValueBytes || hasControl(value) {
				return false
			}
		}
	}
	return true
}

func matches(match CompiledMatch, request Request) bool {
	return matchesCountry(match, request, "")
}

func matchesCountry(match CompiledMatch, request Request, country string) bool {
	if match.Host != "" && !strings.EqualFold(match.Host, strings.TrimSuffix(request.Host, ".")) {
		return false
	}
	if match.Port != 0 && match.Port != request.Port {
		return false
	}
	if match.Method != "" && match.Method != request.Method {
		return false
	}
	if match.Path != nil && !pathMatches(*match.Path, request.Path) {
		return false
	}
	if match.Query != nil && !valueMatches(*match.Query, request.Query, false) {
		return false
	}
	if match.Header != nil && !valueMatches(*match.Header, request.Header, true) {
		return false
	}
	if match.UserAgent != nil && !userAgentMatches(*match.UserAgent, request.Header) {
		return false
	}
	if match.SourceCIDR != nil && !cidrMatches(*match.SourceCIDR, request.SourceAddr) {
		return false
	}
	if match.Country != nil && !countryMatches(*match.Country, country) {
		return false
	}
	return true
}

func countryFor(ranges []CompiledGeoRange, address netip.Addr) string {
	for _, item := range ranges {
		if cidrMatches(item.CIDR, address) {
			return item.Country
		}
	}
	return ""
}

func countryMatches(match CountryMatch, country string) bool {
	if country == "" {
		return false
	}
	found := false
	for _, value := range match.Values {
		if value == country {
			found = true
			break
		}
	}
	if match.Operator == CountryIn {
		return found
	}
	return match.Operator == CountryNotIn && !found
}

func pathMatches(match PathMatch, requestPath string) bool {
	if match.Kind == PathExact {
		return requestPath == match.Value
	}
	if match.Kind == PathRawPrefix {
		return strings.HasPrefix(requestPath, match.Value)
	}
	if match.Value == "/" || requestPath == match.Value {
		return true
	}
	return strings.HasPrefix(requestPath, match.Value+"/")
}

func valueMatches(match ValueMatch, values map[string][]string, foldName bool) bool {
	var found []string
	for name, candidates := range values {
		matchedName := name == match.Name
		if foldName {
			matchedName = strings.EqualFold(name, match.Name)
		}
		if matchedName {
			found = append(found, candidates...)
		}
	}
	if match.Operator == OperatorExists {
		return len(found) > 0
	}
	return len(found) == 1 && found[0] == match.Value
}

func userAgentMatches(match UserAgentMatch, headers map[string][]string) bool {
	value, found, unambiguous := singleHeader(headers, "user-agent")
	if !found || !unambiguous || len(value) > MaxUserAgentBytes || !utf8.ValidString(value) {
		return false
	}
	if match.Operator == OperatorExists {
		return true
	}
	return match.Operator == OperatorExact && value == match.Value
}

func cidrMatches(cidr CompiledCIDR, address netip.Addr) bool {
	if cidr.Family == 4 {
		if !address.Is4() || len(cidr.Network) != 4 || cidr.PrefixLength > 32 {
			return false
		}
		bytes := address.As4()
		return prefixMatches(cidr.Network, bytes[:], cidr.PrefixLength)
	}
	if cidr.Family != 6 || len(cidr.Network) != 16 || cidr.PrefixLength > 128 || !address.Is6() || address.Is4In6() {
		return false
	}
	bytes := address.As16()
	return prefixMatches(cidr.Network, bytes[:], cidr.PrefixLength)
}

func prefixMatches(network []uint16, address []byte, bits uint8) bool {
	fullBytes := int(bits / 8)
	for index := 0; index < fullBytes; index++ {
		if network[index] != uint16(address[index]) {
			return false
		}
	}
	remaining := bits % 8
	if remaining == 0 {
		return true
	}
	mask := uint16(0xff << (8 - remaining))
	return network[fullBytes]&mask == uint16(address[fullBytes])&mask
}
