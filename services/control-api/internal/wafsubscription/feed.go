// Package wafsubscription runs WAF rule libraries fed by a subscription URL
// (NF37, "订阅更新"): the control
// plane fetches the document, compiles it into waf_v2 rule pack rules and
// keeps the last good snapshot (PA-25). A subscribing tenant gets its own
// user layer rule pack (user/<tenant>/waf-sub-<id>); every snapshot whose
// rules changed adds a version of it. The pack goes through the rule pack
// model like any other (download != enable, platform -> tenant -> site,
// conflicts refuse publication): a new version reaches a site only when the
// site is published. Nodes never fetch the URL.
package wafsubscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypublication"
	"github.com/google/uuid"
)

// Document limits. A WAF policy holds at most MaxCompiledRules rules of at most
// securitypolicy.MaxWAFRuleConditions conditions (content conditions may
// repeat a field), so a document that needs more is refused rather than
// truncated.
const (
	MaxDocumentBytes  = 8 << 20
	maxFeedRules      = 5000
	maxGroups         = 10
	maxMatchers       = 10
	MaxCompiledRules  = 100
	maxRuleNameRunes  = 120
	maxFeedTextRunes  = 128
	maxRuleIDRunes    = 128
	maxConditionValue = 256
)

// ErrInvalidDocument is a document that is not a subscription document.
var ErrInvalidDocument = errors.New("invalid WAF subscription document")

// CompileError names the feed rule the node runtime cannot enforce. The
// whole document is refused: dropping a rule silently would weaken (protect)
// or tighten (pass) the library.
type CompileError struct {
	RuleID string
	Reason string
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("rule %q: %s", e.RuleID, e.Reason)
}

// Feed is a compiled subscription document: waf_v2 rule pack rules
// r0001.. in document order (rule IDs sort in execution order), checked by
// libs/rulepack (the compiler the edge agent runs) including its budget.
type Feed struct {
	Version     string
	GeneratedAt string
	Rules       []rulepack.Rule
	SHA256      [sha256.Size]byte
}

type document struct {
	Version     *string        `json:"version"`
	GeneratedAt string         `json:"generated_at"`
	Rules       []documentRule `json:"rules"`
}

type documentRule struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Enable        json.RawMessage   `json:"enable"`
	Action        string            `json:"action"`
	ActionConfig  map[string]any    `json:"action_config"`
	MatcherGroups []documentGrouped `json:"matcher_groups"`
}

type documentGrouped struct {
	Matcher []documentMatcher `json:"matcher"`
}

type documentMatcher struct {
	Field     string `json:"field"`
	Key       string `json:"key"`
	Op        string `json:"op"`
	Value     string `json:"value"`
	Transform string `json:"transform"`
}

// fieldAliases maps document fields to WAF condition fields. Fields the WAF
// runtime does not match (Host, protocol, region, ASN, TLS fingerprint, time)
// are refused.
var fieldAliases = map[string]string{
	"ip": "client_ip", "client_ip": "client_ip", "remote_addr": "client_ip",
	"uri": "path", "path": "path", "path_uri": "path",
	"req_uri": "request_uri", "request_uri": "request_uri", "full_uri": "request_uri",
	"method": "method", "req_method": "method",
	"header": "header", "headers": "header",
	"args": "args", "param": "args", "params": "args",
	"query": "query", "query_string": "query",
	"body": "body", "req_body": "body",
	"cookie": "cookie", "cookies": "cookie",
	"user_agent": "user_agent", "ua": "user_agent",
	"referer": "referer", "referrer": "referer",
	"port": "port",
}

var operatorAliases = map[string]string{
	"equal": "equals", "equals": "equals", "eq": "equals",
	"contain": "contains", "contains": "contains",
	"prefix": "prefix", "starts_with": "prefix",
	"regex": "regex", "match": "regex",
	"ip_range": "ip_in_cidr", "in_ip_range": "ip_in_cidr", "cidr": "ip_in_cidr", "ip_in_cidr": "ip_in_cidr",
}

// inspectFields are matched by the node's request-content inspection, which
// URL-decodes values (up to three times) and compares contains case-folded
// (edgeconfig.WAFInspect); lower / urldecode transforms are therefore exact
// for contains and, with (?i), for regex.
var inspectFields = map[string]bool{
	"args": true, "query": true, "body": true, "request_uri": true, "path": true,
	"header": true, "cookie": true, "user_agent": true, "referer": true,
}

// Compile parses and compiles a subscription document. Each matcher group of
// an enabled rule becomes one WAF policy rule (groups are OR, matchers within
// a group are AND). pass -> allow (stop), observe -> log (continue),
// protect -> block 403 (stop).
func Compile(raw []byte) (Feed, error) {
	if len(raw) > MaxDocumentBytes {
		return Feed{}, fmt.Errorf("%w: larger than %d bytes", ErrInvalidDocument, MaxDocumentBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var parsed document
	if err := decoder.Decode(&parsed); err != nil {
		return Feed{}, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Feed{}, fmt.Errorf("%w: trailing data", ErrInvalidDocument)
	}
	if parsed.Version == nil || !validText(*parsed.Version, maxFeedTextRunes) || strings.TrimSpace(*parsed.Version) == "" ||
		!validText(parsed.GeneratedAt, 64) {
		return Feed{}, fmt.Errorf("%w: version / generated_at", ErrInvalidDocument)
	}
	if len(parsed.Rules) > maxFeedRules {
		return Feed{}, fmt.Errorf("%w: more than %d rules", ErrInvalidDocument, maxFeedRules)
	}
	rules := make([]securitypolicy.Rule, 0)
	seen := make(map[string]bool, len(parsed.Rules))
	for _, item := range parsed.Rules {
		if strings.TrimSpace(item.ID) == "" || !validText(item.ID, maxRuleIDRunes) || seen[item.ID] {
			return Feed{}, fmt.Errorf("%w: rule id %q missing, too long or duplicated", ErrInvalidDocument, item.ID)
		}
		seen[item.ID] = true
		enabled, ok := parseEnable(item.Enable)
		if !ok {
			return Feed{}, &CompileError{RuleID: item.ID, Reason: "enable must be 0, 1, true or false"}
		}
		if !enabled {
			continue
		}
		compiled, err := compileRule(item)
		if err != nil {
			return Feed{}, err
		}
		for _, rule := range compiled {
			rule.Priority = len(rules) + 1
			rules = append(rules, rule)
		}
		if len(rules) > MaxCompiledRules {
			return Feed{}, fmt.Errorf("%w: compiles to more than %d WAF rules (one per matcher group)", ErrInvalidDocument, MaxCompiledRules)
		}
	}
	if len(rules) == 0 {
		return Feed{}, fmt.Errorf("%w: no enabled rule", ErrInvalidDocument)
	}
	normalized, err := securitypolicy.NormalizePublishableWAFRules(rules)
	if err != nil {
		return Feed{}, fmt.Errorf("%w: compiled rules refused by the WAF policy gate", ErrInvalidDocument)
	}
	packRules, err := packRules(normalized)
	if err != nil {
		return Feed{}, err
	}
	encoded, err := json.Marshal(packRules)
	if err != nil {
		return Feed{}, err
	}
	return Feed{Version: strings.TrimSpace(*parsed.Version), GeneratedAt: parsed.GeneratedAt, Rules: packRules,
		SHA256: sha256.Sum256(encoded)}, nil
}

// packRules turns policy rules into waf_v2 rule pack rules with the node
// mapping a bound WAF policy uses, refuses a rule an earlier terminal rule
// shadows (it would never run), and compiles a probe pack so a document the
// rule pack compiler or its budget refuses is refused here, not at the
// first subscriber.
func packRules(rules []securitypolicy.Rule) ([]rulepack.Rule, error) {
	out := make([]rulepack.Rule, 0, len(rules))
	compiled := make([]edgeconfig.WAFRule, 0, len(rules))
	for index, rule := range rules {
		waf, err := securitypublication.CompileWAFRule(rule.Action, rule.Flow, rule.Conditions)
		if err != nil {
			return nil, &CompileError{RuleID: rule.Name, Reason: "not enforceable by the WAF runtime"}
		}
		if securitypublication.WAFRuleShadowed(compiled, waf.Match) {
			return nil, &CompileError{RuleID: rule.Name, Reason: "an earlier stopping rule matches every request it matches"}
		}
		compiled = append(compiled, waf)
		out = append(out, rulepack.Rule{ID: PackRuleID(index), Name: packRuleName(rule.Name), WAF: &waf})
	}
	probe := Pack(uuid.Nil, uuid.Nil, "probe", "", Revision{Major: 1}, out)
	if _, err := rulepack.CompilePack(probe); err != nil {
		return nil, fmt.Errorf("%w: refused by the rule pack compiler: %v", ErrInvalidDocument, err)
	}
	return out, nil
}

// PackRuleID is the pack rule ID of the index-th compiled rule; IDs sort in
// document order, which is the order the pack runs its rules.
func PackRuleID(index int) string { return fmt.Sprintf("r%04d", index+1) }

func packRuleName(name string) string {
	if name = packText(name, 128); name == "" {
		return "rule"
	}
	return name
}

func compileRule(item documentRule) ([]securitypolicy.Rule, error) {
	fail := func(format string, args ...any) error {
		return &CompileError{RuleID: item.ID, Reason: fmt.Sprintf(format, args...)}
	}
	var action, flow string
	switch item.Action {
	case "pass":
		action, flow = securitypolicy.ActionAllow, securitypolicy.FlowStop
	case "observe":
		action, flow = securitypolicy.ActionLog, securitypolicy.FlowContinue
	case "protect":
		action, flow = securitypolicy.ActionBlock, securitypolicy.FlowStop
	default:
		return nil, fail("action %q is not pass, observe or protect", item.Action)
	}
	for key, value := range item.ActionConfig {
		status := fmt.Sprint(value)
		if key != "status" || action != securitypolicy.ActionBlock || status != "403" && status != "" {
			return nil, fail("action_config %s=%v: the node blocks with 403 only", key, value)
		}
	}
	if len(item.MatcherGroups) == 0 || len(item.MatcherGroups) > maxGroups {
		return nil, fail("needs 1 to %d matcher groups", maxGroups)
	}
	name := strings.TrimSpace(item.Name)
	if name == "" {
		name = item.ID
	}
	if !utf8.ValidString(name) {
		return nil, fail("name is not UTF-8")
	}
	if runes := []rune(name); len(runes) > maxRuleNameRunes {
		name = string(runes[:maxRuleNameRunes])
	}
	rules := make([]securitypolicy.Rule, 0, len(item.MatcherGroups))
	for groupIndex, group := range item.MatcherGroups {
		if len(group.Matcher) == 0 || len(group.Matcher) > maxMatchers {
			return nil, fail("group %d needs 1 to %d matchers", groupIndex+1, maxMatchers)
		}
		conditions := make([]securitypolicy.Condition, 0, len(group.Matcher))
		for _, matcher := range group.Matcher {
			condition, err := compileMatcher(matcher)
			if err != nil {
				return nil, fail("group %d: %v", groupIndex+1, err)
			}
			conditions = append(conditions, condition)
		}
		rule := securitypolicy.Rule{Name: name, Priority: 1, Enabled: true, Action: action, Flow: flow, Conditions: conditions}
		if len(item.MatcherGroups) > 1 {
			rule.Name = fmt.Sprintf("%s #%d", name, groupIndex+1)
		}
		if _, err := securitypolicy.NormalizePublishableWAFRules([]securitypolicy.Rule{rule}); err != nil {
			return nil, fail("group %d is not enforceable by the WAF runtime (at most %d conditions, valid values)", groupIndex+1,
				securitypolicy.MaxWAFRuleConditions)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func compileMatcher(matcher documentMatcher) (securitypolicy.Condition, error) {
	field, ok := fieldAliases[strings.ToLower(strings.TrimSpace(matcher.Field))]
	if !ok {
		return securitypolicy.Condition{}, fmt.Errorf("field %q is not matched by the WAF runtime", matcher.Field)
	}
	operator, ok := operatorAliases[strings.ToLower(strings.TrimSpace(matcher.Op))]
	if !ok {
		return securitypolicy.Condition{}, fmt.Errorf("op %q is not supported", matcher.Op)
	}
	value := matcher.Value
	if utf8.RuneCountInString(value) > maxConditionValue {
		return securitypolicy.Condition{}, fmt.Errorf("value longer than %d characters", maxConditionValue)
	}
	key := strings.TrimSpace(matcher.Key)
	if field != "header" && key != "" {
		// A keyed parameter/cookie would widen to every parameter/cookie.
		return securitypolicy.Condition{}, fmt.Errorf("field %s with key %q is not matched per key", field, key)
	}
	switch {
	case field == "client_ip" && operator == "equals":
		operator = "ip_in_cidr"
	case field == "port" && operator == "equals":
		operator = "number_eq"
	}
	switch strings.ToLower(strings.TrimSpace(matcher.Transform)) {
	case "", "none":
	case "lower", "lowercase":
		if !inspectFields[field] || operator != "contains" && operator != "regex" {
			return securitypolicy.Condition{}, fmt.Errorf("transform lower on %s %s is not exact", field, operator)
		}
		if operator == "regex" && !strings.HasPrefix(value, "(?i)") {
			value = "(?i)" + value
		}
	case "urldecode", "url_decode":
		if !inspectFields[field] || operator != "contains" && operator != "regex" {
			return securitypolicy.Condition{}, fmt.Errorf("transform urldecode on %s %s is not exact", field, operator)
		}
	default:
		return securitypolicy.Condition{}, fmt.Errorf("transform %q is not supported", matcher.Transform)
	}
	return securitypolicy.Condition{Field: field, Operator: operator, Key: key, Values: []string{value}}, nil
}

func parseEnable(raw json.RawMessage) (bool, bool) {
	switch strings.TrimSpace(string(raw)) {
	case "1", "true":
		return true, true
	case "0", "false":
		return false, true
	}
	return false, false
}

func validText(value string, runes int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= runes && !strings.ContainsAny(value, "\x00\r\n")
}
