package ccv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

func CompileSource(raw []byte, binding Binding) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxSourceBytes || rejectDuplicateJSONKeys(raw) != nil ||
		!canonicalUUID(binding.BindingID) || binding.BindingRevision < 1 || binding.BindingRevision > 1<<53-1 ||
		!canonicalUUID(binding.PublicationID) {
		return nil, ErrInvalidSource
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var source sourcePolicy
	if decoder.Decode(&source) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidSource
	}
	canonicalSource, err := json.Marshal(source)
	if err != nil || !bytes.Equal(canonicalSource, raw) || validateSourcePolicy(source) != nil {
		return nil, ErrInvalidSource
	}
	compiled := compiledPolicy{
		SchemaVersion: CompiledSchemaVersion, TenantScopeID: source.TenantScopeID, SiteID: source.SiteID,
		PolicyID: source.PolicyID, PolicyVersion: source.PolicyVersion, BindingID: binding.BindingID,
		BindingRevision: binding.BindingRevision, PublicationID: binding.PublicationID, Enabled: source.Enabled,
		TrustedProxies: []string{}, Allowlist: []string{}, Rules: []compiledRule{},
	}
	if source.Enabled {
		if compiled.Rules, err = compileRules(source.Rules); err != nil {
			return nil, ErrInvalidSource
		}
		// An auto switch whose rules are all disabled is no auto switch.
		if value := source.AutoSwitch; value != nil {
			rules, compileErr := compileRules(value.Rules)
			if compileErr != nil {
				return nil, ErrInvalidSource
			}
			if len(rules) > 0 {
				compiled.AutoSwitch = &compiledAutoSwitch{QPSTotal: uint32(value.QPSTotal), QPS5xx: uint32(value.QPS5xx),
					RecoverSeconds: uint32(value.RecoverSeconds), Rules: rules}
			}
		}
		// CC API v6: only an enabled policy carries them.
		compiled.TrustedCrawlers = source.TrustedCrawlers
		compiled.ChallengeCookieDomain = source.ChallengeCookieDomain
	}
	result, err := json.Marshal(compiled)
	if err != nil {
		return nil, fmt.Errorf("marshal CC v2 policy: %w", err)
	}
	return result, nil
}

// compileRules compiles the enabled rules in node order.
func compileRules(source []sourceRule) ([]compiledRule, error) {
	rules := []compiledRule{}
	for _, rule := range source {
		if !rule.Enabled {
			continue
		}
		value, err := compileRule(rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, value)
	}
	sort.Slice(rules, func(left, right int) bool {
		if rules[left].Priority != rules[right].Priority {
			return rules[left].Priority < rules[right].Priority
		}
		return rules[left].RuleID < rules[right].RuleID
	})
	return rules, nil
}

func validateSourcePolicy(source sourcePolicy) error {
	if source.SchemaVersion != SourceSchemaVersion || source.Kind != "cc" || source.DefaultAction != "allow" ||
		!canonicalUUID(source.TenantScopeID) || !canonicalUUID(source.SiteID) || !canonicalUUID(source.PolicyID) ||
		source.PolicyVersion < 1 || source.PolicyVersion > 1<<53-1 || source.Rules == nil || len(source.Rules) > MaxRules {
		return ErrInvalidSource
	}
	seen := make(map[string]struct{}, len(source.Rules))
	if err := validateSourceRules(source.Rules, seen); err != nil {
		return err
	}
	if validateTrustedCrawlers(source.TrustedCrawlers) != nil ||
		source.ChallengeCookieDomain != "" && !validCookieDomain(source.ChallengeCookieDomain) {
		return ErrInvalidSource
	}
	// The auto switch (securitypolicy.normalizeCCSettings): a threshold, a
	// recovery of 1 minute to 1 day and 1..100 rules whose IDs differ from
	// the policy's.
	if value := source.AutoSwitch; value != nil {
		if value.QPSTotal < 0 || value.QPSTotal > 1_000_000 || value.QPS5xx < 0 || value.QPS5xx > 1_000_000 ||
			value.QPSTotal == 0 && value.QPS5xx == 0 || value.RecoverSeconds < 60 || value.RecoverSeconds > 86_400 ||
			value.Rules == nil || len(value.Rules) < 1 || len(value.Rules) > 100 {
			return ErrInvalidSource
		}
		return validateSourceRules(value.Rules, seen)
	}
	return nil
}

// validateSourceRules checks one ordered rule set; seen collects rule IDs.
func validateSourceRules(rules []sourceRule, seen map[string]struct{}) error {
	previousPriority, previousID := -1, ""
	for _, rule := range rules {
		if !canonicalUUID(rule.ID) || rule.Priority < 1 || rule.Priority > 1_000_000 || len(rule.Conditions) < 1 ||
			len(rule.Conditions) > 16 || rule.Flow != "continue" && rule.Flow != "stop" ||
			!(rule.Action == "rate_limit" && rule.ActionConfig.RateLimit != nil && rule.ActionConfig.Challenge == nil ||
				rule.Action == "challenge" && rule.ActionConfig.Challenge != nil && rule.ActionConfig.RateLimit == nil) {
			return ErrInvalidSource
		}
		if _, duplicate := seen[rule.ID]; duplicate || rule.Priority < previousPriority ||
			rule.Priority == previousPriority && rule.ID <= previousID {
			return ErrInvalidSource
		}
		seen[rule.ID] = struct{}{}
		previousPriority, previousID = rule.Priority, rule.ID
		// Strictly ascending in control's order (securitypolicy
		// compareConditions: field, operator, key, values).
		for index := 1; index < len(rule.Conditions); index++ {
			if compareConditions(rule.Conditions[index-1], rule.Conditions[index]) >= 0 {
				return ErrInvalidSource
			}
		}
	}
	return nil
}

func compareConditions(left, right sourceCondition) int {
	if result := strings.Compare(left.Field, right.Field); result != 0 {
		return result
	}
	if result := strings.Compare(left.Operator, right.Operator); result != 0 {
		return result
	}
	if result := strings.Compare(left.Key, right.Key); result != 0 {
		return result
	}
	return slices.Compare(left.Values, right.Values)
}

// validateTrustedCrawlers (CC API v6) re-checks the canonical crawler list
// control stores: 1..32 crawlers by distinct name, each with sorted distinct
// User-Agent tokens and at least one verification (masked CIDRs other than
// /0, or rDNS suffixes of two labels or more).
func validateTrustedCrawlers(crawlers []trustedCrawler) error {
	if crawlers == nil {
		return nil
	}
	if len(crawlers) == 0 || len(crawlers) > 32 {
		return ErrInvalidSource
	}
	for index, crawler := range crawlers {
		if len(crawler.Name) == 0 || len(crawler.Name) > 64 || strings.Trim(crawler.Name, "abcdefghijklmnopqrstuvwxyz0123456789-_.") != "" ||
			index > 0 && crawlers[index-1].Name >= crawler.Name || crawler.Networks == nil && crawler.RDNSSuffixes == nil ||
			!sortedStrings(crawler.UserAgentTokens, 16, func(value string) bool {
				return len(value) >= 3 && len(value) <= 128 && strings.IndexFunc(value, func(r rune) bool { return r <= ' ' || r > '~' }) < 0
			}) ||
			crawler.Networks != nil && !sortedStrings(crawler.Networks, 256, func(value string) bool {
				prefix, err := netip.ParsePrefix(value)
				return err == nil && !prefix.Addr().Is4In6() && prefix.Bits() > 0 && prefix.Masked().String() == value
			}) ||
			crawler.RDNSSuffixes != nil && !sortedStrings(crawler.RDNSSuffixes, 16, validCookieDomain) {
			return ErrInvalidSource
		}
	}
	return nil
}

// sortedStrings: 1..maximum valid values in strictly ascending order.
func sortedStrings(values []string, maximum int, valid func(string) bool) bool {
	if len(values) < 1 || len(values) > maximum {
		return false
	}
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

// validCookieDomain: a lower-case DNS name of two labels or more.
func validCookieDomain(value string) bool {
	host, err := normalizeHost(value)
	return err == nil && host == value && strings.Contains(value, ".")
}

func compileRule(rule sourceRule) (compiledRule, error) {
	result, err := compileRuleMatchAndAction(rule)
	if err != nil {
		return compiledRule{}, err
	}
	return compileCountBy(result, rule)
}

// countKeyOrder is the canonical order of counting keys (control-api
// securitypolicy.countKeyOrder).
var countKeyOrder = []string{"client_ip", "client_cidr", "host", "uri", "uri_path", "ja4",
	// CC API v7 (fix-ja4rule).
	"user_agent", "referer", "header", "cookie", "query"}

// CC API v7 names and fingerprints, re-derived independently of control:
// a count key's header (lower case) / cookie / query argument name, and the
// JA4 shape the native module emits (edgeconfig.JA4Pattern).
var (
	countHeaderNamePattern = regexp.MustCompile(`^[a-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64}$`)
	countParamNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]{1,128}$`)
	ja4Pattern             = regexp.MustCompile(`^[tqd](?:1[0-3]|s[23]|d[1-3]|00)[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
)

func validCountKeyName(key sourceCountKey) bool {
	switch key.Key {
	case "header":
		return countHeaderNamePattern.MatchString(key.Name)
	case "cookie", "query":
		return countParamNamePattern.MatchString(key.Name)
	}
	return key.Name == ""
}

// compileCountBy independently re-derives the control-api counting keys (CC
// API v4): only the canonical form control stores is accepted (one or two
// distinct keys in countKeyOrder, never client_ip alone, client_cidr with
// both prefixes, not client_ip+client_cidr or uri+uri_path, no per-client
// statistics, a challenge only through its trigger). action_target
// count_key is only a temporary ban's.
func compileCountBy(result compiledRule, rule sourceRule) (compiledRule, error) {
	if rule.ActionTarget != "" && (rule.ActionTarget != "count_key" || rule.CountBy == nil ||
		result.Action.Kind != "temporary_ban") {
		return compiledRule{}, ErrInvalidSource
	}
	if rule.CountBy == nil {
		return result, nil
	}
	if len(rule.CountBy) < 1 || len(rule.CountBy) > 2 || len(rule.CountBy) == 1 && rule.CountBy[0].Key == "client_ip" ||
		result.Match.DistinctUserAgents != 0 || result.Match.Status404Count != 0 ||
		result.Action.Kind == "challenge" && result.Limit.Algorithm != "fixed_window" {
		return compiledRule{}, ErrInvalidSource
	}
	seen := map[string]bool{}
	previous := -1
	result.CountBy = make([]compiledCountKey, 0, len(rule.CountBy))
	for _, key := range rule.CountBy {
		position := -1
		for index, name := range countKeyOrder {
			if name == key.Key {
				position = index
			}
		}
		if position <= previous {
			return compiledRule{}, ErrInvalidSource
		}
		previous = position
		seen[key.Key] = true
		if key.Key == "client_cidr" {
			if key.IPv4Prefix < 8 || key.IPv4Prefix > 32 || key.IPv6Prefix < 32 || key.IPv6Prefix > 128 {
				return compiledRule{}, ErrInvalidSource
			}
		} else if key.IPv4Prefix != 0 || key.IPv6Prefix != 0 {
			return compiledRule{}, ErrInvalidSource
		}
		if !validCountKeyName(key) {
			return compiledRule{}, ErrInvalidSource
		}
		result.CountBy = append(result.CountBy, compiledCountKey{Key: key.Key, IPv4Prefix: uint32(key.IPv4Prefix),
			IPv6Prefix: uint32(key.IPv6Prefix), Name: key.Name})
	}
	if seen["client_ip"] && seen["client_cidr"] || seen["uri"] && seen["uri_path"] {
		return compiledRule{}, ErrInvalidSource
	}
	result.Action.Target = rule.ActionTarget
	return result, nil
}

func compileRuleMatchAndAction(rule sourceRule) (compiledRule, error) {
	result := compiledRule{RuleID: rule.ID, Priority: rule.Priority, Flow: rule.Flow, Dimension: "client_ip"}
	seen := make(map[string]struct{}, len(rule.Conditions))
	ipConditions := []sourceCondition{}
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
			header, err := compileHeaderMatch(condition)
			if err != nil {
				return compiledRule{}, err
			}
			result.Match.Headers = append(result.Match.Headers, header)
			continue
		case "ja4":
			// CC API v7: equals (one) / in, sorted unique fingerprints.
			if condition.Key != "" || result.Match.JA4 != nil || len(condition.Values) < 1 || len(condition.Values) > 64 ||
				condition.Operator != "equals" && condition.Operator != "in" || condition.Operator == "equals" && len(condition.Values) != 1 {
				return compiledRule{}, ErrInvalidSource
			}
			for index, value := range condition.Values {
				if !ja4Pattern.MatchString(value) || index > 0 && condition.Values[index-1] >= value {
					return compiledRule{}, ErrInvalidSource
				}
			}
			result.Match.JA4 = slices.Clone(condition.Values)
			continue
		}
		pathContains := field == "path" && condition.Operator == "contains"
		if condition.Key != "" || len(condition.Values) != 1 && !pathContains {
			return compiledRule{}, ErrInvalidSource
		}
		if _, duplicate := seen[field]; duplicate {
			return compiledRule{}, ErrInvalidSource
		}
		seen[field] = struct{}{}
		value := condition.Values[0]
		switch {
		case pathContains:
			if len(condition.Values) < 1 || len(condition.Values) > 64 {
				return compiledRule{}, ErrInvalidSource
			}
			result.Match.PathContains = append([]string(nil), condition.Values...)
			sort.Strings(result.Match.PathContains)
		case field == "host" && condition.Operator == "equals":
			host, err := normalizeHost(value)
			if err != nil || host != value {
				return compiledRule{}, ErrInvalidSource
			}
			result.Match.Host = host
		case field == "method" && condition.Operator == "equals" && validMethod(value):
			result.Match.Method = value
		case field == "path" && (condition.Operator == "equals" || condition.Operator == "prefix"):
			if !validPath(value) {
				return compiledRule{}, ErrInvalidSource
			}
			kind := "exact"
			if condition.Operator == "prefix" {
				kind = "prefix"
			}
			result.Match.Path = &compiledPathMatch{Kind: kind, Value: value}
		case field == "port" && condition.Operator == "number_eq":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 || strconv.FormatUint(port, 10) != value {
				return compiledRule{}, ErrInvalidSource
			}
			result.Match.Port = uint16(port)
		case field == "distinct_user_agents" && condition.Operator == "number_gte":
			count, err := strconv.ParseUint(value, 10, 32)
			if err != nil || count < 1 || count > 1024 || strconv.FormatUint(count, 10) != value {
				return compiledRule{}, ErrInvalidSource
			}
			result.Match.DistinctUserAgents = uint32(count)
		case field == "status_404_count" && condition.Operator == "number_gte":
			count, err := strconv.ParseUint(value, 10, 32)
			if err != nil || count < 1 || count > 1024 || strconv.FormatUint(count, 10) != value {
				return compiledRule{}, ErrInvalidSource
			}
			result.Match.Status404Count = uint32(count)
		default:
			return compiledRule{}, ErrInvalidSource
		}
	}
	if err := compileClientIP(&result.Match, ipConditions); err != nil {
		return compiledRule{}, err
	}
	if rule.Action == "challenge" {
		return compileChallenge(result, *rule.ActionConfig.Challenge, rule.Flow)
	}
	limit := rule.ActionConfig.RateLimit
	if limit.Adaptive != nil {
		return compiledRule{}, ErrInvalidSource
	}
	algorithm := limit.Algorithm
	if algorithm == "" {
		algorithm = "fixed_window"
	}
	switch algorithm {
	case "fixed_window":
		if limit.MaxRequests < 1 || limit.MaxRequests > 1_000_000 || limit.WindowSeconds < 1 || limit.WindowSeconds > 3600 ||
			limit.MaxPerURI < 0 || limit.MaxPerURI > 1_000_000 || limit.RatePerSecond != 0 || limit.Burst != 0 {
			return compiledRule{}, ErrInvalidSource
		}
		result.Limit = compiledLimit{Algorithm: algorithm, Requests: uint32(limit.MaxRequests), PerURI: uint32(limit.MaxPerURI),
			WindowSeconds: uint32(limit.WindowSeconds)}
	case "leaky_bucket":
		if limit.RatePerSecond < 1 || limit.RatePerSecond > 1_000_000 || limit.Burst < 1 || limit.Burst > 1_000_000 ||
			limit.MaxRequests != 0 || limit.WindowSeconds != 0 || limit.MaxPerURI != 0 || result.Match.DistinctUserAgents != 0 ||
			result.Match.Status404Count != 0 {
			return compiledRule{}, ErrInvalidSource
		}
		result.Limit = compiledLimit{Algorithm: algorithm, RatePerSecond: uint32(limit.RatePerSecond), Burst: uint32(limit.Burst)}
	default:
		return compiledRule{}, ErrInvalidSource
	}
	action := limit.ResponseAction
	if action == "" {
		action = "reject_429"
	}
	result.Action = compiledAction{Kind: action, BanSeconds: uint32(limit.BanSeconds)}
	switch action {
	case "log":
		if limit.BanSeconds != 0 || rule.Flow != "continue" && rule.Flow != "stop" {
			return compiledRule{}, ErrInvalidSource
		}
	case "reject_429":
		if limit.BanSeconds != 0 || rule.Flow != "stop" {
			return compiledRule{}, ErrInvalidSource
		}
	case "temporary_ban":
		if limit.BanSeconds < 1 || limit.BanSeconds > 86_400 || rule.Flow != "stop" {
			return compiledRule{}, ErrInvalidSource
		}
	default:
		return compiledRule{}, ErrInvalidSource
	}
	return result, nil
}

// compileClientIP independently re-derives control's client_ip compilation
// (securitypublication.withCCV2ClientIP): one equals / ip_in_cidr condition
// with one value is source_cidr; otherwise one client_ip entry per condition
// (ip_not_in_cidr negated). Values are canonical: an address for equals,
// masked CIDRs in ascending order for the CIDR operators.
func compileClientIP(match *compiledMatch, conditions []sourceCondition) error {
	entries := make([]compiledIPMatch, 0, len(conditions))
	for _, condition := range conditions {
		if condition.Key != "" || len(condition.Values) < 1 || len(condition.Values) > 256 {
			return ErrInvalidSource
		}
		var cidrs []string
		switch condition.Operator {
		case "equals":
			address, err := netip.ParseAddr(condition.Values[0])
			if len(condition.Values) != 1 || err != nil || address.Is4In6() || address.Zone() != "" ||
				address.String() != condition.Values[0] {
				return ErrInvalidSource
			}
			cidrs = []string{netip.PrefixFrom(address, address.BitLen()).String()}
		case "ip_in_cidr", "ip_not_in_cidr":
			for index, value := range condition.Values {
				prefix, err := netip.ParsePrefix(value)
				if err != nil || prefix.Addr().Is4In6() || prefix.Masked().String() != value ||
					index > 0 && condition.Values[index-1] >= value {
					return ErrInvalidSource
				}
			}
			cidrs = append([]string(nil), condition.Values...)
		default:
			return ErrInvalidSource
		}
		entries = append(entries, compiledIPMatch{Negate: condition.Operator == "ip_not_in_cidr", CIDRs: cidrs})
	}
	switch {
	case len(entries) == 0:
	case len(entries) > 16:
		return ErrInvalidSource
	case len(entries) == 1 && !entries[0].Negate && len(entries[0].CIDRs) == 1:
		match.SourceCIDR = entries[0].CIDRs[0]
	default:
		match.ClientIP = entries
	}
	return nil
}

var headerKinds = map[string]string{"equals": "exact", "prefix": "prefix", "contains": "contains", "regex": "regex"}

// compileHeaderMatch independently re-derives a header / user_agent /
// referer condition (CC API v6): the lower-case header name (user-agent /
// referer for those fields, the condition key for header), the match kind
// and the sorted distinct values (regex values must compile).
func compileHeaderMatch(condition sourceCondition) (compiledHeaderMatch, error) {
	name := condition.Key
	switch condition.Field {
	case "user_agent":
		name = "user-agent"
	case "referer":
		name = "referer"
	}
	kind, known := headerKinds[condition.Operator]
	if !known || (condition.Field == "header") == (condition.Key == "") || !validHeaderName(name) ||
		len(condition.Values) < 1 || len(condition.Values) > 64 {
		return compiledHeaderMatch{}, ErrInvalidSource
	}
	for index, value := range condition.Values {
		if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 ||
			index > 0 && condition.Values[index-1] >= value {
			return compiledHeaderMatch{}, ErrInvalidSource
		}
		if kind == "regex" {
			if _, err := regexp.Compile(value); err != nil {
				return compiledHeaderMatch{}, ErrInvalidSource
			}
		}
	}
	return compiledHeaderMatch{Name: name, Kind: kind, Values: append([]string(nil), condition.Values...)}, nil
}

// validHeaderName: a lower-case HTTP field name token.
func validHeaderName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			strings.ContainsRune("!#$%&'*+.^_`|~-", character)) {
			return false
		}
	}
	return true
}

var challengeModes = map[string]string{
	"five_second": "delay", "js": "js", "redirect": "redirect", "click": "click", "simple_click": "easy_click",
	"slider": "slider", "simple_slider": "easy_slider", "captcha": "captcha", "rotate_image": "rotate",
}

// compileChallenge independently re-derives the control-api challenge
// compilation. Every value is required from the source policy; nothing is
// defaulted (the catalog / operator supplies all of them).
func compileChallenge(result compiledRule, config sourceChallenge, flow string) (compiledRule, error) {
	mode, known := challengeModes[config.Type]
	within := func(value, minimum, maximum int) bool { return value >= minimum && value <= maximum }
	optional := func(value, minimum, maximum int) bool { return value == 0 || within(value, minimum, maximum) }
	pow := mode == "redirect" && config.PowBits == 0 || mode != "redirect" && within(config.PowBits, 8, 26)
	if !known || flow != "stop" || result.Match.DistinctUserAgents != 0 || result.Match.Status404Count != 0 ||
		!within(config.FailureWindowSeconds, 1, 86_400) || !within(config.MaxFailures, 1, 1000) ||
		!within(config.PassSeconds, 60, 7*86_400) || !optional(config.BanSeconds, 1, 86_400) ||
		config.LogOnly != (config.BanSeconds == 0) || !pow ||
		(mode == "delay") != (config.DelaySeconds != 0) || !optional(config.DelaySeconds, 1, 30) ||
		!within(config.ChallengeSeconds, 30, 3600) || !within(config.BindIPv4Prefix, 8, 32) ||
		!within(config.BindIPv6Prefix, 32, 128) || !within(config.KeyRotateSeconds, config.PassSeconds, 30*86_400) ||
		(config.TriggerWindowSeconds == 0) != (config.TriggerMaxRequests == 0) ||
		!optional(config.TriggerWindowSeconds, 1, 3600) || !optional(config.TriggerMaxRequests, 1, 1_000_000) ||
		(config.PassWindowSeconds == 0) != (config.PassMaxRequests == 0) ||
		!optional(config.PassWindowSeconds, 1, 3600) || !optional(config.PassMaxRequests, 1, 1_000_000) ||
		!optional(config.PassMaxRequestsPerURI, 1, 1_000_000) || config.PassMaxRequestsPerURI != 0 && config.PassWindowSeconds == 0 {
		return compiledRule{}, ErrInvalidSource
	}
	challenge := &compiledChallenge{Mode: mode, FailureWindowSeconds: uint32(config.FailureWindowSeconds),
		MaxFailures: uint32(config.MaxFailures), PassSeconds: uint32(config.PassSeconds), LogOnly: config.LogOnly,
		DelaySeconds: uint32(config.DelaySeconds), PowBits: uint32(config.PowBits),
		ChallengeSeconds: uint32(config.ChallengeSeconds), BindIPv4Prefix: uint32(config.BindIPv4Prefix),
		BindIPv6Prefix: uint32(config.BindIPv6Prefix), KeyRotateSeconds: uint32(config.KeyRotateSeconds)}
	if config.PassWindowSeconds != 0 {
		challenge.PassLimit = &compiledLimit{Algorithm: "fixed_window", Requests: uint32(config.PassMaxRequests),
			PerURI: uint32(config.PassMaxRequestsPerURI), WindowSeconds: uint32(config.PassWindowSeconds)}
	}
	result.Action = compiledAction{Kind: "challenge", Challenge: challenge, BanSeconds: uint32(config.BanSeconds)}
	result.Limit = compiledLimit{Algorithm: "always"}
	if config.TriggerWindowSeconds != 0 {
		result.Limit = compiledLimit{Algorithm: "fixed_window", Requests: uint32(config.TriggerMaxRequests),
			WindowSeconds: uint32(config.TriggerWindowSeconds)}
	}
	return result, nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func normalizeHost(value string) (string, error) {
	if len(value) == 0 || len(value) > 253 || !ascii(value) || strings.ContainsAny(value, ":/\\%") ||
		strings.HasSuffix(value, ".") || strings.ToLower(value) != value {
		return "", ErrInvalidSource
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidSource
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", ErrInvalidSource
		}
	}
	return value, nil
}

func validMethod(value string) bool {
	if len(value) == 0 || len(value) > 32 || strings.ToUpper(value) != value {
		return false
	}
	const separators = "()<>@,;:\\\"/[]?={} \t"
	for _, character := range value {
		if character < 0x21 || character > 0x7e || strings.ContainsRune(separators, character) {
			return false
		}
	}
	return true
}

func validPath(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) || value[0] != '/' ||
		strings.ContainsAny(value, "\\%?#") || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if unicode.IsControl(character) {
				return false
			}
		}
	}
	return true
}

func ascii(value string) bool {
	for _, character := range value {
		if character > unicode.MaxASCII || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
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
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidSource
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalidSource
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidSource
		}
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalidSource
	}
	return nil
}
