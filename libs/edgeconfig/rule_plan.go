package edgeconfig

import (
	"bytes"
	"encoding/json"
	"time"
)

// Rule plan: the data form of a listener's ACL / WAF security rules that the
// request-time interpreter edge/openresty/lua/cdnca_rule_interp.lua executes
// (ADR 0009 §4 "ACL/WAF 自研规则"). It carries exactly the semantics of the
// rendered state machine (renderWAFBlock): ordered segments, each with a
// default action and rules where the last matching rule wins until a "stop"
// rule matches; a segment that ends in block exits 403, log records telemetry
// and goes on, allow goes on. Conditions of one rule are an ordered AND chain
// evaluated left to right with short circuit, in the renderer's order.
//
// The plan is internal IR: the dynamic-routing site object (cdnca.edge.site/v2)
// embeds or references it; nothing in the release path produces it yet.

const RulePlanSchema = "cdnca.edge.rule-plan/v1"

// Plan limits: a layered plan (rule packs) is bounded by these, not by the
// two-policy / MaxSecurityRulesPerSite limits of bound site policies.
const (
	MaxRulePlanSegments = 32
	// MaxRulePlanRules: official rules only accumulate (ADR 0011 §6.5); a
	// plan this large is run through its match index (libs/rulepack
	// CompileMatchIndex), whose compiled cost budget is the real bound.
	MaxRulePlanRules = 65536
)

type RulePlanHeaderOverflow string

const (
	// RulePlanHeaderNone: no rule of any segment reads request headers.
	RulePlanHeaderNone RulePlanHeaderOverflow = "none"
	// RulePlanHeaderBlock: headers are read before the first segment; more
	// than 100 request headers exit 403 without telemetry.
	RulePlanHeaderBlock RulePlanHeaderOverflow = "block"
	// RulePlanHeaderNoMatch: more than 100 request headers are logged and the
	// header conditions see no headers.
	RulePlanHeaderNoMatch RulePlanHeaderOverflow = "no_match"
)

type RulePlanLayer string

const (
	RulePlanLayerUser      RulePlanLayer = "user"
	RulePlanLayerDeveloper RulePlanLayer = "developer"
	RulePlanLayerSystem    RulePlanLayer = "system"
)

// rank is the execution rank of a layer (libs/rulepack Layer.Rank): user
// exceptions first, then developer rules, then system rules.
func (layer RulePlanLayer) rank() int {
	switch layer {
	case RulePlanLayerUser:
		return 0
	case RulePlanLayerDeveloper:
		return 1
	case RulePlanLayerSystem:
		return 2
	}
	return -1
}

// Condition operators. Field use: value (string), number (integer), name
// (lower-case header name), values (sorted string set).
const (
	RuleOpExpiresBefore = "expires_before"  // number: ngx.time() < number
	RuleOpHostEq        = "host_eq"         // value: $host == value
	RuleOpPortEq        = "port_eq"         // number: tonumber($server_port) == number
	RuleOpMethodEq      = "method_eq"       // value: request method == value
	RuleOpPathExact     = "path_exact"      // value: $uri == value
	RuleOpPathPrefix    = "path_prefix"     // value: $uri == value or starts with value.."/"
	RuleOpPathRawPrefix = "path_raw_prefix" // value: $uri starts with value
	RuleOpHeaderExists  = "header_exists"   // name
	RuleOpHeaderEq      = "header_eq"       // name, value: single string header == value
	RuleOpSourceCIDR    = "source_cidr"     // value: canonical CIDR; $remote_addr inside (v4-mapped v6 as v4)
	RuleOpJA4In         = "ja4_in"          // values: $cdnca_ja4 in values
	RuleOpJA4NotIn      = "ja4_not_in"      // values: $cdnca_ja4 non-empty and not in values (WAF_JA4_NEGATION)
	RuleOpIPIntel       = "ip_intel"        // value: cdnca_iplib.match(value) spec
	RuleOpInspect       = "inspect"         // value: cdnca_waf.inspect(value) JSON
	RuleOpIPList        = "ip_list"         // value: cdnca_waf.ip_list(value) spec (IPListConditionSpec)
)

type RulePlan struct {
	Schema         string                 `json:"schema"`
	HeaderOverflow RulePlanHeaderOverflow `json:"header_overflow"`
	// Telemetry: block / log decisions set the cdnca_security_* variables.
	Telemetry bool              `json:"telemetry"`
	Segments  []RulePlanSegment `json:"segments"`
	// Index is the compiled match index (libs/rulepack MatchIndex,
	// cdnca.edge.rule-index/v1); without it the interpreter tries every rule.
	Index json.RawMessage `json:"index,omitempty"`
}

type RulePlanSegment struct {
	// Layer is set for rule-pack segments (CompileLayeredRulePlan) only.
	Layer RulePlanLayer `json:"layer,omitempty"`
	Kind  SecurityKind  `json:"kind"`
	// Provenance of the bound policy (not read by the interpreter).
	PolicyID        string `json:"policy_id"`
	PolicyVersion   int64  `json:"policy_version"`
	BindingRevision int64  `json:"binding_revision"`
	RuntimeSHA256   string `json:"runtime_sha256"`
	// Enabled false: no rule runs (Rules is empty), DefaultAction still applies.
	Enabled       bool           `json:"enabled"`
	DefaultAction WAFAction      `json:"default_action"`
	DefaultRuleID string         `json:"default_rule_id"`
	Rules         []RulePlanRule `json:"rules"`
	// Action is the segment's WAF v2 action spec (WAFActionSpecJSON) when the
	// policy has challenge / ban rules, auto block or observe mode: the
	// interpreter runs cdnca_waf.gate before the rules and cdnca_waf.act
	// for the verdict, as the renderer does. Empty otherwise.
	Action string `json:"action,omitempty"`
}

type RulePlanRule struct {
	RuleID     string              `json:"rule_id"`
	Action     WAFAction           `json:"action"`
	Flow       WAFControl          `json:"flow"`
	Conditions []RulePlanCondition `json:"conditions"`
}

type RulePlanCondition struct {
	Op     string   `json:"op"`
	Name   string   `json:"name,omitempty"`
	Value  string   `json:"value,omitempty"`
	Number *int64   `json:"number,omitempty"`
	Values []string `json:"values,omitempty"`
}

// RulePlanSegmentInput is one rule-pack segment of a layered plan, in
// execution order (user, then developer, then system).
type RulePlanSegmentInput struct {
	Layer  RulePlanLayer
	Policy SecurityPolicy
}

// CompileSecurityRulePlan compiles one listener's bound security policies
// (ListenerSecurity.Policies) into the plan that behaves exactly like the
// rewrite_by_lua_block RenderSecurityFragmentsAt renders for them.
// overflowBlocks is headerOverflowBlocks of the site (managed WAF inspection
// limit action block); telemetry is SecurityListener.Telemetry.
func CompileSecurityRulePlan(policies []SecurityPolicy, overflowBlocks, telemetry bool) (RulePlan, error) {
	return CompileSiteSecurityRulePlan("", policies, overflowBlocks, telemetry)
}

// CompileSiteSecurityRulePlan is CompileSecurityRulePlan for the listener of
// site siteID (the WAF v2 ban scope, as RenderSecurityFragmentsAt renders it).
func CompileSiteSecurityRulePlan(siteID string, policies []SecurityPolicy, overflowBlocks, telemetry bool) (RulePlan, error) {
	normalized, err := normalizeSecurityPolicies(policies)
	if err != nil {
		return RulePlan{}, err
	}
	return buildRulePlan(normalized, nil, overflowBlocks, telemetry, siteID)
}

// CompileLayeredRulePlan compiles ordered rule-pack segments. Each segment
// policy is validated like a bound policy (header and every rule), segments
// must not go back in layer rank, and the plan limits apply.
func CompileLayeredRulePlan(segments []RulePlanSegmentInput, overflowBlocks, telemetry bool) (RulePlan, error) {
	policies, layers, err := normalizeRulePlanSegments(segments)
	if err != nil {
		return RulePlan{}, err
	}
	return buildRulePlan(policies, layers, overflowBlocks, telemetry)
}

// normalizeRulePlanSegments validates layered segments; the result is what
// renderWAFBlock would run for the same order.
func normalizeRulePlanSegments(segments []RulePlanSegmentInput) ([]SecurityPolicy, []RulePlanLayer, error) {
	if len(segments) > MaxRulePlanSegments {
		return nil, nil, ErrInvalidConfig
	}
	policies := make([]SecurityPolicy, len(segments))
	layers := make([]RulePlanLayer, len(segments))
	total := 0
	for index, segment := range segments {
		if segment.Layer.rank() < 0 || index > 0 && segment.Layer.rank() < layers[index-1].rank() {
			return nil, nil, ErrInvalidConfig
		}
		header := segment.Policy
		header.Rules = nil
		normalized, err := normalizeSecurityPolicies([]SecurityPolicy{header})
		if err != nil {
			return nil, nil, err
		}
		total += len(segment.Policy.Rules)
		if total > MaxRulePlanRules {
			return nil, nil, ErrInvalidConfig
		}
		policy := normalized[0]
		policy.Rules = make([]WAFRule, len(segment.Policy.Rules))
		for ruleIndex, rule := range segment.Policy.Rules {
			if policy.Rules[ruleIndex], err = normalizeSecurityRule(rule); err != nil {
				return nil, nil, err
			}
		}
		policies[index], layers[index] = policy, segment.Layer
	}
	return policies, layers, nil
}

// buildRulePlan maps normalized policies (renderWAFBlock's input) to the plan.
// siteID scopes WAF v2 bans (WAFActionSpecJSON); "" for a plan without one.
func buildRulePlan(policies []SecurityPolicy, layers []RulePlanLayer, overflowBlocks, telemetry bool, siteID ...string) (RulePlan, error) {
	site := ""
	if len(siteID) > 0 {
		site = siteID[0]
	}
	plan := RulePlan{Schema: RulePlanSchema, HeaderOverflow: RulePlanHeaderNone, Telemetry: telemetry,
		Segments: make([]RulePlanSegment, len(policies))}
	for index, policy := range policies {
		segment := RulePlanSegment{Kind: policy.Kind, PolicyID: policy.PolicyID, PolicyVersion: policy.PolicyVersion,
			BindingRevision: policy.BindingRevision, RuntimeSHA256: policy.RuntimeSHA256, Enabled: policy.Enabled,
			DefaultAction: policy.DefaultAction, DefaultRuleID: policy.PolicyID + ":default", Rules: []RulePlanRule{}}
		if layers != nil {
			segment.Layer = layers[index]
		}
		if SecurityPolicyUsesWAFActions(policy) {
			segment.Action = WAFActionSpecJSON(site, policy, telemetry)
		}
		for _, rule := range policy.Rules {
			// renderWAFBlock reads the headers when any rule of any policy,
			// enabled or not, has a header condition.
			if rule.Match.Header != nil {
				plan.HeaderOverflow = RulePlanHeaderNoMatch
				if overflowBlocks {
					plan.HeaderOverflow = RulePlanHeaderBlock
				}
			}
			if !policy.Enabled {
				continue
			}
			conditions, err := rulePlanConditions(rule)
			if err != nil {
				return RulePlan{}, err
			}
			segment.Rules = append(segment.Rules, RulePlanRule{RuleID: rule.RuleID, Action: rule.Action, Flow: rule.Control,
				Conditions: conditions})
		}
		plan.Segments[index] = segment
	}
	return plan, nil
}

// rulePlanConditions is renderBoundSecurityCondition as data, same order.
func rulePlanConditions(rule WAFRule) ([]RulePlanCondition, error) {
	match := rule.Match
	conditions := make([]RulePlanCondition, 0, 6)
	number := func(value int64) *int64 { return &value }
	if rule.ExpiresAt != "" {
		expiresAt, err := time.Parse("2006-01-02T15:04:05Z", rule.ExpiresAt)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		conditions = append(conditions, RulePlanCondition{Op: RuleOpExpiresBefore, Number: number(expiresAt.Unix())})
	}
	if match.Host != "" {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpHostEq, Value: match.Host})
	}
	if match.Port != 0 {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpPortEq, Number: number(int64(match.Port))})
	}
	if match.Method != "" {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpMethodEq, Value: match.Method})
	}
	if match.Path != nil {
		op := RuleOpPathPrefix
		switch match.Path.Kind {
		case WAFPathExact:
			op = RuleOpPathExact
		case WAFPathRawPrefix:
			op = RuleOpPathRawPrefix
		}
		conditions = append(conditions, RulePlanCondition{Op: op, Value: match.Path.Value})
	}
	if match.Header != nil {
		if match.Header.Kind == WAFHeaderExists {
			conditions = append(conditions, RulePlanCondition{Op: RuleOpHeaderExists, Name: match.Header.Name})
		} else {
			conditions = append(conditions, RulePlanCondition{Op: RuleOpHeaderEq, Name: match.Header.Name, Value: match.Header.Value})
		}
	}
	if match.SourceCIDR != "" {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpSourceCIDR, Value: match.SourceCIDR})
	}
	if match.JA4 != nil {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpJA4In, Values: append([]string(nil), match.JA4...)})
	}
	if match.NotJA4 != nil {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpJA4NotIn, Values: append([]string(nil), match.NotJA4...)})
	}
	for _, condition := range match.IPIntel {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpIPIntel, Value: IPIntelConditionSpec(condition)})
	}
	for _, list := range match.IPLists {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpIPList, Value: IPListConditionSpec(list)})
	}
	for _, inspect := range match.Inspect {
		conditions = append(conditions, RulePlanCondition{Op: RuleOpInspect, Value: wafInspectJSON(inspect)})
	}
	return conditions, nil
}

// EncodeRulePlan is the canonical plan JSON: struct field order, compact, no
// HTML escaping, no trailing newline.
func EncodeRulePlan(plan RulePlan) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(plan); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// wafInspectJSON is the inspect clause JSON the renderer embeds and
// cdnca_waf.inspect caches by.
func wafInspectJSON(value WAFInspect) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
