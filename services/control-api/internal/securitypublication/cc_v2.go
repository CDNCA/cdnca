package securitypublication

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

// compileCCV2 compiles a CC binding for a server serving domains (nil: the
// site's primary only, the legacy single-domain server).
func compileCCV2(site edgeconfig.Site, domains []string, binding ActiveBinding) (*edgeconfig.CCV2SiteBinding, error) {
	snapshot := binding.Snapshot
	if snapshot.Kind != securitypolicy.KindCC || snapshot.DefaultAction != securitypolicy.ActionAllow ||
		binding.BindingID == [16]byte{} {
		return nil, ErrUnsupportedRuntime
	}
	policy := edgeconfig.CCV2Policy{
		SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: snapshot.TenantScopeID.String(),
		SiteID: snapshot.SiteID.String(), PolicyID: snapshot.PolicyID.String(), PolicyVersion: snapshot.PolicyVersion,
		BindingID: binding.BindingID.String(), BindingRevision: binding.BindingRevision,
		PublicationID: binding.PublicationID.String(), Enabled: snapshot.Enabled,
		TrustedProxies: []string{}, Allowlist: []string{}, Rules: []edgeconfig.CCV2Rule{},
	}
	if snapshot.Enabled {
		rules, err := compileCCV2Rules(site, domains, snapshot.Rules)
		if err != nil {
			return nil, err
		}
		policy.Rules = rules
		// An auto switch whose rules are all disabled is no auto switch.
		if value := snapshot.AutoSwitch; value != nil {
			switchRules, err := compileCCV2Rules(site, domains, value.Rules)
			if err != nil {
				return nil, err
			}
			if len(switchRules) > 0 {
				policy.AutoSwitch = &edgeconfig.CCV2AutoSwitch{QPSTotal: uint32(value.QPSTotal), QPS5xx: uint32(value.QPS5xx),
					RecoverSeconds: uint32(value.RecoverSeconds), Rules: switchRules}
			}
			if len(value.Overrides) != 0 {
				if policy.AutoSwitch, err = compileCCV2AutoSwitchOverrides(site, domains, value, switchRules); err != nil {
					return nil, err
				}
			}
		}
		// Trusted crawlers and the pass cookie domain (CC API v6) only matter
		// to an enabled policy.
		for _, crawler := range snapshot.TrustedCrawlers {
			policy.TrustedCrawlers = append(policy.TrustedCrawlers, edgeconfig.CCV2TrustedCrawler{Name: crawler.Name,
				UserAgentTokens: append([]string(nil), crawler.UserAgentTokens...),
				Networks:        append([]string(nil), crawler.Networks...),
				RDNSSuffixes:    append([]string(nil), crawler.RDNSSuffixes...)})
		}
		// A crawler named like a default one also verifies by the official
		// IP ranges the license service fetched (dataset/trusted-crawlers).
		merged, err := crawlerdefaults.Merge(policy.TrustedCrawlers, binding.TrustedCrawlers)
		if err != nil {
			return nil, ErrUnsupportedRuntime
		}
		policy.TrustedCrawlers = merged
		policy.ChallengeCookieDomain = snapshot.ChallengeCookieDomain
	}
	canonical, err := edgeconfig.CanonicalCCV2Policy(policy)
	if err != nil {
		return nil, ErrUnsupportedRuntime
	}
	digest := sha256.Sum256(canonical)
	return &edgeconfig.CCV2SiteBinding{SourceSHA256: hex.EncodeToString(binding.RuntimeSnapshotSHA256[:]),
		CompiledSHA256: hex.EncodeToString(digest[:]), Policy: policy}, nil
}

// ccV2HostServed: host is a domain the server serves (the primary without
// domains), a wildcard one ("*.x.example", matched by the engine as nginx
// server_name does), or an exact host under a served wildcard.
func ccV2HostServed(site edgeconfig.Site, domains []string, host string) bool {
	if len(domains) == 0 {
		domains = []string{site.Domain}
	}
	for _, domain := range domains {
		if host == domain {
			return true
		}
		if suffix, wildcard := strings.CutPrefix(domain, "*"); wildcard && !strings.HasPrefix(host, "*") &&
			len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// compileCCV2Rules compiles the enabled rules in node order.
func compileCCV2Rules(site edgeconfig.Site, domains []string, source []securitypolicy.RuntimeRule) ([]edgeconfig.CCV2Rule, error) {
	rules := []edgeconfig.CCV2Rule{}
	for _, rule := range source {
		if !rule.Enabled {
			continue
		}
		compiled, err := compileCCV2Rule(site, domains, rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, compiled)
	}
	sort.Slice(rules, func(left, right int) bool {
		if rules[left].Priority != rules[right].Priority {
			return rules[left].Priority < rules[right].Priority
		}
		return rules[left].RuleID < rules[right].RuleID
	})
	return rules, nil
}

func compileCCV2Rule(site edgeconfig.Site, domains []string, rule securitypolicy.RuntimeRule) (edgeconfig.CCV2Rule, error) {
	compiled, err := compileCCV2RuleMatchAndAction(site, domains, rule)
	if err != nil {
		return edgeconfig.CCV2Rule{}, err
	}
	return withCCV2CountBy(compiled, rule)
}

// withCCV2CountBy carries the rule's counting keys (CC API v4) into the
// compiled rule; a rule without them keeps its pre-v4 bytes. Never dropped:
// counting a /24 threshold per client IP would never trigger.
func withCCV2CountBy(result edgeconfig.CCV2Rule, rule securitypolicy.RuntimeRule) (edgeconfig.CCV2Rule, error) {
	if rule.CountBy != nil {
		result.CountBy = make([]edgeconfig.CCV2CountKey, len(rule.CountBy))
		for index, key := range rule.CountBy {
			if key.IPv4Prefix < 0 || key.IPv6Prefix < 0 {
				return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
			}
			result.CountBy[index] = edgeconfig.CCV2CountKey{Key: edgeconfig.CCV2CountKeyName(key.Key),
				IPv4Prefix: uint32(key.IPv4Prefix), IPv6Prefix: uint32(key.IPv6Prefix), Name: key.Name}
		}
	}
	result.Action.Target = edgeconfig.CCV2ActionTarget(rule.ActionTarget)
	return result, nil
}

func compileCCV2RuleMatchAndAction(site edgeconfig.Site, domains []string, rule securitypolicy.RuntimeRule) (edgeconfig.CCV2Rule, error) {
	if rule.ID == [16]byte{} || rule.Priority < 0 ||
		!(rule.Action == securitypolicy.ActionRateLimit && rule.ActionConfig.RateLimit != nil && rule.ActionConfig.Challenge == nil ||
			rule.Action == securitypolicy.ActionChallenge && rule.ActionConfig.Challenge != nil && rule.ActionConfig.RateLimit == nil) {
		return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
	}
	result := edgeconfig.CCV2Rule{RuleID: rule.ID.String(), Priority: rule.Priority,
		Flow: edgeconfig.CCV2Flow(rule.Flow), Dimension: edgeconfig.CCV2DimensionClientIP}
	seen := make(map[string]struct{}, len(rule.Conditions))
	ipConditions := []securitypolicy.Condition{}
	for _, condition := range rule.Conditions {
		field := condition.Field
		if field == "access_port" {
			field = "port"
		}
		// client_ip and header conditions may repeat (CC API v6, all hold).
		switch field {
		case "client_ip":
			ipConditions = append(ipConditions, condition)
			continue
		case "header", "user_agent", "referer":
			header, err := ccV2HeaderMatch(condition)
			if err != nil {
				return edgeconfig.CCV2Rule{}, err
			}
			result.Match.Headers = append(result.Match.Headers, header)
			continue
		case "ja4":
			// CC API v7 (fix-ja4rule): equals / in, one condition per rule.
			values, err := edgeconfig.NormalizeWAFJA4(append([]string(nil), condition.Values...))
			if err != nil || condition.Key != "" || result.Match.JA4 != nil ||
				condition.Operator != "equals" && condition.Operator != "in" || condition.Operator == "equals" && len(values) != 1 {
				return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
			}
			result.Match.JA4 = values
			continue
		}
		if condition.Key != "" || len(condition.Values) != 1 && !(field == "path" && condition.Operator == "contains") {
			return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
		}
		if _, duplicate := seen[field]; duplicate {
			return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
		}
		seen[field] = struct{}{}
		value := condition.Values[0]
		switch {
		case field == "host" && condition.Operator == "equals" && ccV2HostServed(site, domains, value):
			result.Match.Host = value
		case field == "method" && condition.Operator == "equals":
			result.Match.Method = value
		case field == "path" && condition.Operator == "contains":
			result.Match.PathContains = append([]string(nil), condition.Values...)
			sort.Strings(result.Match.PathContains)
		case field == "path" && (condition.Operator == "equals" || condition.Operator == "prefix"):
			kind := edgeconfig.CCV2PathExact
			if condition.Operator == "prefix" {
				kind = edgeconfig.CCV2PathPrefix
			}
			result.Match.Path = &edgeconfig.CCV2PathMatch{Kind: kind, Value: value}
		case field == "port" && condition.Operator == "number_eq":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 || strconv.FormatUint(port, 10) != value {
				return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
			}
			result.Match.Port = uint16(port)
		case field == "distinct_user_agents" && condition.Operator == "number_gte":
			count, err := strconv.ParseUint(value, 10, 32)
			if err != nil || count < 1 || count > 1024 || strconv.FormatUint(count, 10) != value {
				return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
			}
			result.Match.DistinctUserAgents = uint32(count)
		case field == "status_404_count" && condition.Operator == "number_gte":
			count, err := strconv.ParseUint(value, 10, 32)
			if err != nil || count < 1 || count > 1024 || strconv.FormatUint(count, 10) != value {
				return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
			}
			result.Match.Status404Count = uint32(count)
		default:
			return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
		}
	}
	if err := withCCV2ClientIP(&result.Match, ipConditions); err != nil {
		return edgeconfig.CCV2Rule{}, err
	}
	if rule.Action == securitypolicy.ActionChallenge {
		return compileCCV2Challenge(result, *rule.ActionConfig.Challenge)
	}
	limit := rule.ActionConfig.RateLimit
	algorithm := limit.Algorithm
	if algorithm == "" {
		algorithm = string(edgeconfig.CCV2AlgorithmFixedWindow)
	}
	switch edgeconfig.CCV2Algorithm(algorithm) {
	case edgeconfig.CCV2AlgorithmFixedWindow:
		if limit.Adaptive != nil {
			return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
		}
		result.Limit = edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow,
			Requests: uint32(limit.MaxRequests), PerURI: uint32(limit.MaxPerURI), WindowSeconds: uint32(limit.WindowSeconds)}
	case edgeconfig.CCV2AlgorithmLeakyBucket:
		if limit.Adaptive != nil || result.Match.DistinctUserAgents != 0 || result.Match.Status404Count != 0 {
			return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
		}
		result.Limit = edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmLeakyBucket,
			RatePerSecond: uint32(limit.RatePerSecond), Burst: uint32(limit.Burst)}
	default:
		return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
	}
	action := limit.ResponseAction
	if action == "" {
		action = string(edgeconfig.CCV2ActionReject429)
	}
	result.Action = edgeconfig.CCV2Action{Kind: edgeconfig.CCV2ActionKind(action), BanSeconds: uint32(limit.BanSeconds)}
	return result, nil
}

// withCCV2ClientIP compiles a rule's client_ip conditions (in condition
// order): one equals / ip_in_cidr condition with one value is source_cidr
// (the pre-v6 bytes); anything else is the CC v6 client_ip list, one entry
// per condition (ip_not_in_cidr negated, an address as its host CIDR).
func withCCV2ClientIP(match *edgeconfig.CCV2Match, conditions []securitypolicy.Condition) error {
	entries := make([]edgeconfig.CCV2IPMatch, 0, len(conditions))
	for _, condition := range conditions {
		if condition.Key != "" || len(condition.Values) == 0 ||
			condition.Operator != "equals" && condition.Operator != "ip_in_cidr" && condition.Operator != "ip_not_in_cidr" ||
			condition.Operator == "equals" && len(condition.Values) != 1 {
			return ErrUnsupportedRuntime
		}
		cidrs := make([]string, len(condition.Values))
		for index, value := range condition.Values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return ErrUnsupportedRuntime
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			if prefix.Addr().Is4In6() {
				return ErrUnsupportedRuntime
			}
			cidrs[index] = prefix.Masked().String()
		}
		sort.Strings(cidrs)
		entries = append(entries, edgeconfig.CCV2IPMatch{Negate: condition.Operator == "ip_not_in_cidr", CIDRs: cidrs})
	}
	switch {
	case len(entries) == 0:
	case len(entries) == 1 && !entries[0].Negate && len(entries[0].CIDRs) == 1:
		match.SourceCIDR = entries[0].CIDRs[0]
	default:
		match.ClientIP = entries
	}
	return nil
}

// ccV2HeaderMatch compiles a header / user_agent / referer condition (CC API
// v6) into the lower-case header name, the match kind and its values.
func ccV2HeaderMatch(condition securitypolicy.Condition) (edgeconfig.CCV2HeaderMatch, error) {
	name := condition.Key
	switch condition.Field {
	case "user_agent":
		name = "user-agent"
	case "referer":
		name = "referer"
	}
	if name == "" || (condition.Field != "header") != (condition.Key == "") {
		return edgeconfig.CCV2HeaderMatch{}, ErrUnsupportedRuntime
	}
	kinds := map[string]edgeconfig.CCV2HeaderKind{"equals": edgeconfig.CCV2HeaderExact, "prefix": edgeconfig.CCV2HeaderPrefix,
		"contains": edgeconfig.CCV2HeaderContains, "regex": edgeconfig.CCV2HeaderRegex}
	kind, known := kinds[condition.Operator]
	if !known || len(condition.Values) == 0 {
		return edgeconfig.CCV2HeaderMatch{}, ErrUnsupportedRuntime
	}
	values := append([]string(nil), condition.Values...)
	sort.Strings(values)
	return edgeconfig.CCV2HeaderMatch{Name: name, Kind: kind, Values: values}, nil
}

var challengeModes = map[string]string{
	"five_second": "delay", "js": "js", "redirect": "redirect", "click": "click", "simple_click": "easy_click",
	"slider": "slider", "simple_slider": "easy_slider", "captcha": "captcha", "rotate_image": "rotate",
}

func compileCCV2Challenge(result edgeconfig.CCV2Rule, config securitypolicy.ChallengeConfig) (edgeconfig.CCV2Rule, error) {
	mode, known := challengeModes[config.Type]
	if !known || result.Flow != edgeconfig.CCV2FlowStop || result.Match.DistinctUserAgents != 0 || result.Match.Status404Count != 0 {
		return edgeconfig.CCV2Rule{}, ErrUnsupportedRuntime
	}
	// Every value is the policy's own (validated by securitypolicy); none is
	// defaulted here.
	challenge := &edgeconfig.CCV2Challenge{Mode: mode,
		FailureWindowSeconds: uint32(config.FailureWindowSeconds), MaxFailures: uint32(config.MaxFailures),
		PassSeconds: uint32(config.PassSeconds), LogOnly: config.LogOnly, DelaySeconds: uint32(config.DelaySeconds),
		PowBits: uint32(config.PowBits), ChallengeSeconds: uint32(config.ChallengeSeconds),
		BindIPv4Prefix: uint32(config.BindIPv4Prefix), BindIPv6Prefix: uint32(config.BindIPv6Prefix),
		KeyRotateSeconds: uint32(config.KeyRotateSeconds)}
	if config.PassWindowSeconds != 0 {
		challenge.PassLimit = &edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow,
			Requests: uint32(config.PassMaxRequests), PerURI: uint32(config.PassMaxRequestsPerURI),
			WindowSeconds: uint32(config.PassWindowSeconds)}
	}
	result.Action = edgeconfig.CCV2Action{Kind: edgeconfig.CCV2ActionChallenge, Challenge: challenge,
		BanSeconds: uint32(config.BanSeconds)}
	result.Limit = edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmAlways}
	if config.TriggerWindowSeconds != 0 {
		result.Limit = edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow,
			Requests: uint32(config.TriggerMaxRequests), WindowSeconds: uint32(config.TriggerWindowSeconds)}
	}
	return result, nil
}

// compileCCV2AutoSwitchOverrides is the auto switch with its per-node
// overrides (CC API v8, fix-fwregion). Rule sets whose rules are all
// disabled turn their overrides off; an override running the global rules
// while those are all disabled is off too. No override left: the plain
// global switch (nil when it is off).
func compileCCV2AutoSwitchOverrides(site edgeconfig.Site, domains []string, value *securitypolicy.RuntimeAutoSwitch,
	globalRules []edgeconfig.CCV2Rule) (*edgeconfig.CCV2AutoSwitch, error) {
	sets := map[string]bool{}
	result := &edgeconfig.CCV2AutoSwitch{Rules: []edgeconfig.CCV2Rule{}}
	if len(globalRules) > 0 {
		result.QPSTotal, result.QPS5xx, result.RecoverSeconds = uint32(value.QPSTotal), uint32(value.QPS5xx), uint32(value.RecoverSeconds)
		result.Rules = globalRules
	}
	for _, set := range value.RuleSets {
		rules, err := compileCCV2Rules(site, domains, set.Rules)
		if err != nil {
			return nil, err
		}
		if len(rules) > 0 {
			sets[set.Group] = true
			result.RuleSets = append(result.RuleSets, edgeconfig.CCV2AutoSwitchRuleSet{Name: set.Group, Rules: rules})
		}
	}
	for _, override := range value.Overrides {
		item := edgeconfig.CCV2AutoSwitchOverride{Nodes: make([]string, 0, len(override.Nodes))}
		for _, node := range override.Nodes {
			item.Nodes = append(item.Nodes, node.String())
		}
		sort.Strings(item.Nodes)
		runs := override.RuleGroup != "" && (override.RuleGroup == value.RuleGroup && len(globalRules) > 0 || sets[override.RuleGroup])
		if runs {
			item.QPSTotal, item.QPS5xx, item.RecoverSeconds = uint32(override.QPSTotal), uint32(override.QPS5xx), uint32(override.RecoverSeconds)
			if override.RuleGroup != value.RuleGroup || len(globalRules) == 0 {
				item.RuleSet = override.RuleGroup
			}
		}
		if !runs && len(globalRules) == 0 {
			continue // off where global is off
		}
		result.Overrides = append(result.Overrides, item)
	}
	// Rule sets no remaining override uses are dropped.
	used := map[string]bool{}
	for _, override := range result.Overrides {
		used[override.RuleSet] = true
	}
	kept := result.RuleSets[:0]
	for _, set := range result.RuleSets {
		if used[set.Name] {
			kept = append(kept, set)
		}
	}
	result.RuleSets = kept
	if len(result.RuleSets) == 0 {
		result.RuleSets = nil
	}
	sort.Slice(result.Overrides, func(left, right int) bool { return result.Overrides[left].Nodes[0] < result.Overrides[right].Nodes[0] })
	switch {
	case len(result.Overrides) != 0:
		return result, nil
	case len(globalRules) > 0:
		result.Overrides = nil
		return result, nil
	}
	return nil, nil
}
