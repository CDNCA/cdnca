package securitypolicy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// ErrCatalogUnsupported reports a signed catalog item the node runtime cannot
// enforce yet. Expansion fails closed instead of silently dropping semantics.
var ErrCatalogUnsupported = errors.New("system rule catalog item is not enforceable by the node runtime")

// catalogChallengeTypes maps catalog filter types to node verification pages.
var catalogChallengeTypes = map[string]string{
	"browser_verify_auto": "js", "delay_jump_filter": "five_second", "click_filter": "click",
	"easy_click_filter": "simple_click", "slide_filter": "slider", "easy_slide_filter": "simple_slider",
	"captcha_filter": "captcha", "rotate_filter": "rotate_image", "302_challenge": "redirect",
}

// legacyCCFilterParams are the enforcement parameters, by filter type, of the
// catalog's filters with params (license-service migration 065,
// rulecatalog.CompetitorFilterParams): blacklist 360 s and pass 21600 s as
// before params existed, plus the proof-of-work defaults of the type.
var legacyCCFilterParams = func() map[string]rulecatalog.CCFilterParams {
	params := map[string]rulecatalog.CCFilterParams{}
	for _, item := range rulecatalog.CompetitorFilterParams() {
		params[item.Body.CCFilter.Type] = *item.Body.CCFilter.Params
	}
	return params
}()

// ExpandCCRuleGroup turns a catalog CC rule group into concrete CC policy
// rules (IDs left nil for the caller to assign). Every number comes
// from the catalog filter (counts, window, CCFilterParams):
//   - req_rate: more than max_req requests (or max_req_per_uri to one URI) within
//     within_second -> action (block = blacklist params.ban_seconds, log = record).
//   - verification filters: a client without a valid pass gets the page
//     (proof of work params.pow_bits); failing it more than max_req times
//     within within_second -> action. Passing grants a params.pass_seconds
//     pass limited by the hidden "临时白名单" filter (cc_filter:11).
//   - filter1 + filter2 (page-catalog.md "过滤器1 失败后再用过滤器2，两者都失败才
//     执行动作"): filter1 must be req_rate without a per-URI budget and filter2
//     a verification filter. The entry becomes one challenge rule of filter2
//     that only triggers after more than filter1 max_req requests within
//     filter1 within_second (ChallengeConfig.Trigger*); failing the page then
//     runs the action as above. Other pairs are ErrCatalogUnsupported.
//
// A filter without params (catalogs of license services before migration 065,
// and every catalog served to a control release below
// rulecatalog.EngineCatalogControlVersion) uses legacyCCFilterParams of its
// type; params that are present must be valid (ErrCatalogUnsupported).
func ExpandCCRuleGroup(items map[string]rulecatalog.Item, groupKey string) ([]Rule, error) {
	group, ok := items[groupKey]
	if !ok || group.Kind != rulecatalog.KindCCRuleGroup || group.Body.CCRuleGroup == nil {
		return nil, fmt.Errorf("%w: %s", ErrCatalogUnsupported, groupKey)
	}
	passLimit := items["cc_filter:11"].Body.CCFilter
	rules := make([]Rule, 0, len(group.Body.CCRuleGroup.Entries))
	for index, entry := range group.Body.CCRuleGroup.Entries {
		if !entry.Enabled {
			continue
		}
		matcher, matcherOK := items[entry.MatcherKey]
		filter, filterOK := items[entry.Filter1Key]
		if !matcherOK || !filterOK || matcher.Body.CCMatcher == nil || filter.Body.CCFilter == nil {
			return nil, fmt.Errorf("%w: %s entry %d", ErrCatalogUnsupported, groupKey, index+1)
		}
		var trigger *rulecatalog.CCFilterBody
		if entry.Filter2Key != "" {
			rate, second := *filter.Body.CCFilter, items[entry.Filter2Key]
			if second.Body.CCFilter == nil || second.Body.CCFilter.Type == "req_rate" || rate.Type != "req_rate" || rate.MaxReqPerURI != 0 || rate.MaxReq < 1 ||
				rate.WithinSecond > 3600 {
				return nil, fmt.Errorf("%w: %s entry %d filter pair", ErrCatalogUnsupported, groupKey, index+1)
			}
			trigger = &rate
			filter = rulecatalog.Item{SystemKey: entry.Filter2Key, Name: filter.Name + " → " + second.Name,
				Body: second.Body}
		}
		conditions, err := catalogMatcherConditions(*matcher.Body.CCMatcher)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", err, entry.MatcherKey)
		}
		flow := FlowStop
		if entry.Mode == "continue" {
			flow = FlowContinue
		}
		rule := Rule{Name: group.Name + " · " + filter.Name, Priority: index + 1, Enabled: true,
			Conditions: conditions, Flow: flow}
		config := *filter.Body.CCFilter
		params, known := legacyCCFilterParams[config.Type]
		if config.Params != nil {
			params = *config.Params
		}
		if !known && config.Params == nil || !rulecatalog.ValidCCFilterParams(config.Type, params) {
			return nil, fmt.Errorf("%w: %s has no enforcement parameters", ErrCatalogUnsupported, filter.SystemKey)
		}
		if config.Type == "req_rate" {
			limit := &RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: config.WithinSecond,
				MaxRequests: config.MaxReq, MaxPerURI: config.MaxReqPerURI}
			switch entry.Action {
			case "block":
				limit.ResponseAction, limit.BanSeconds, rule.Flow = "temporary_ban", params.BanSeconds, FlowStop
			case "log":
				limit.ResponseAction = "log"
			default:
				return nil, fmt.Errorf("%w: %s action %s", ErrCatalogUnsupported, groupKey, entry.Action)
			}
			rule.Action, rule.ActionConfig.RateLimit = ActionRateLimit, limit
		} else {
			challengeType, known := catalogChallengeTypes[config.Type]
			if !known || entry.Action != "block" && entry.Action != "log" {
				return nil, fmt.Errorf("%w: %s filter %s", ErrCatalogUnsupported, groupKey, config.Type)
			}
			challenge := &ChallengeConfig{Type: challengeType, FailureWindowSeconds: config.WithinSecond,
				MaxFailures: config.MaxReq, PassSeconds: params.PassSeconds, LogOnly: entry.Action == "log",
				PowBits: params.PowBits, DelaySeconds: params.DelaySeconds, ChallengeSeconds: params.ChallengeSeconds,
				BindIPv4Prefix: params.BindIPv4Prefix, BindIPv6Prefix: params.BindIPv6Prefix,
				KeyRotateSeconds: params.KeyRotateSeconds}
			if !challenge.LogOnly {
				challenge.BanSeconds = params.BanSeconds
			}
			if config.MaxReq == 0 {
				challenge.MaxFailures = 1
			}
			if passLimit != nil {
				challenge.PassWindowSeconds, challenge.PassMaxRequests = passLimit.WithinSecond, passLimit.MaxReq
				challenge.PassMaxRequestsPerURI = passLimit.MaxReqPerURI
			}
			if trigger != nil {
				challenge.TriggerWindowSeconds, challenge.TriggerMaxRequests = trigger.WithinSecond, trigger.MaxReq
			}
			rule.Action, rule.ActionConfig.Challenge, rule.Flow = ActionChallenge, challenge, FlowStop
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// catalogWAFDetectors binds node semantic detectors to catalog rule sets: the
// signatures alone miss encoded/obfuscated payloads, the detectors tokenise
// the decoded value (libinjection-style SQL fingerprints, HTML/attribute XSS,
// template expressions that evaluate, Java object streams with a valid class
// descriptor or gadget class, PHP objects whose declared class name length
// matches and phar://).
var catalogWAFDetectors = map[string]string{"waf_set:sqli": "sqli", "waf_set:xss": "xss", "waf_set:ssti": "ssti",
	"waf_set:java_deserialization": "java_deser", "waf_set:php_deserialization": "php_deser"}

var catalogWAFFields = map[string]string{
	"args": "args", "query": "query", "body": "body", "req_uri": "request_uri", "uri": "path",
	"header": "header", "cookie": "cookie", "user_agent": "user_agent", "referer": "referer",
	"upload_extension": "upload_extension", "upload_filename": "upload_filename",
	"multipart_field_names": "multipart_field_names",
}

// catalogWAFOperators maps catalog matcher operators to WAF content
// operators (edgeconfig.WAFInspect).
var catalogWAFOperators = map[string]string{
	"contain": "contains", "not_contain": "not_contains", "regex": "regex", "not_regex": "not_regex",
	"equal": "equals", "not_equal": "not_equals", "prefix": "prefix", "suffix": "suffix",
}

// ExpandWAFRuleSets turns catalog WAF rule sets into WAF policy rules (IDs left
// nil). Each matcher group becomes one rule (groups are OR, matchers within a
// group are AND). action "" keeps the catalog action, "log" / "block"
// overrides it (仅记录 / 拦截). Block rules stop, log rules continue.
func ExpandWAFRuleSets(items map[string]rulecatalog.Item, setKeys []string, action string) ([]Rule, error) {
	if action != "" && action != ActionLog && action != ActionBlock {
		return nil, ErrInvalidInput
	}
	rules := make([]Rule, 0)
	add := func(name, ruleAction string, conditions []Condition) {
		if action != "" {
			ruleAction = action
		}
		flow := FlowContinue
		if ruleAction == ActionBlock {
			flow = FlowStop
		}
		rules = append(rules, Rule{Name: name, Priority: len(rules) + 1, Enabled: true, Action: ruleAction, Flow: flow,
			Conditions: conditions})
	}
	for _, key := range setKeys {
		set, ok := items[key]
		if !ok || set.Kind != rulecatalog.KindWAFRuleSet || set.Body.WAFRuleSet == nil {
			return nil, fmt.Errorf("%w: %s", ErrCatalogUnsupported, key)
		}
		if detector := catalogWAFDetectors[key]; detector != "" {
			add(set.Name+" · 语义检测", ActionLog, []Condition{{Field: "args", Operator: "detect", Values: []string{detector}}})
		}
		for _, catalogRule := range set.Body.WAFRuleSet.Rules {
			if !catalogRule.Enabled {
				continue
			}
			if catalogRule.Action != ActionLog && catalogRule.Action != ActionBlock {
				return nil, fmt.Errorf("%w: %s rule %s action %s", ErrCatalogUnsupported, key, catalogRule.ID, catalogRule.Action)
			}
			for _, group := range catalogRule.MatcherGroups {
				conditions := make([]Condition, 0, len(group.Matchers))
				for _, matcher := range group.Matchers {
					field := catalogWAFFields[matcher.Field]
					operator := catalogWAFOperators[matcher.Operator]
					if field == "" || operator == "" || matcher.Transform != "none" && matcher.Transform != "urldecode" &&
						matcher.Transform != "lowercase" {
						return nil, fmt.Errorf("%w: %s rule %s matcher %s/%s", ErrCatalogUnsupported, key, catalogRule.ID,
							matcher.Field, matcher.Operator)
					}
					conditions = append(conditions, Condition{Field: field, Operator: operator,
						Key: strings.ToLower(matcher.Key), Values: []string{matcher.Value}})
				}
				add(set.Name+" · "+catalogRule.Name, catalogRule.Action, conditions)
			}
		}
	}
	return rules, nil
}

func catalogMatcherConditions(matcher rulecatalog.CCMatcherBody) ([]Condition, error) {
	if len(matcher.Conditions) == 0 {
		return []Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}}, nil
	}
	conditions := make([]Condition, 0, len(matcher.Conditions))
	for _, condition := range matcher.Conditions {
		if condition.Operator != "contain" || condition.Field != "uri" && condition.Field != "req_uri" ||
			len(conditions) > 0 {
			return nil, ErrCatalogUnsupported
		}
		// req_uri (with query) is approximated by the path; the seed values
		// are file names and extensions, which never sit in a query string.
		conditions = append(conditions, Condition{Field: "path", Operator: "contains",
			Values: append([]string(nil), condition.Values...)})
	}
	return conditions, nil
}
