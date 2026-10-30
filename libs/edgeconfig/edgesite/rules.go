package edgesite

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// RulePlan is the site's ACL/WAF rules as data for the node's rule
// interpreter (dynamic routing task D6). It replaces the inline Lua the v7
// renderer generates (edgeconfig renderWAFBlock / renderBoundSecurityCondition)
// and must decide every request exactly as that Lua does:
//
//   - Policies run in order, in the rewrite phase, after CC and the managed
//     WAF.
//   - Within one policy: action := DefaultAction, rule := "<policy_id>:default".
//     If Enabled, each rule in order whose match holds and that is not after a
//     stopping match sets action := rule.action and rule := rule.rule_id; a
//     matching rule with flow "stop" ends the scan. So the last matching rule
//     before a stop wins (not the first).
//   - Then: action "block" -> 403 (security event type = kind, action block,
//     severity high, block page, rule id = rule); "log" -> security event
//     (action log, severity info) and go on; "allow" -> go on to the next
//     policy. An "allow" never skips later policies.
//   - A match holds when every present field holds (AND):
//     expires_at (RFC 3339 UTC "2006-01-02T15:04:05Z"): now < expires_at;
//     host: $host equals it; port: the public port (proxy protocol server port
//     or $server_port) equals it; method: request method equals it;
//     path: kind exact -> $uri equals value; prefix -> $uri equals value or
//     starts with value + "/"; raw_prefix -> $uri starts with value;
//     header: kind exists -> the lower-cased name is present; exact -> present
//     once (not repeated) with exactly that value; source_cidr: the client
//     address is in it; ja4: the request's JA4 fingerprint (native patch 21
//     variable) equals one of the values; ip_intel:
//     each condition per edgeconfig.WAFIPIntel; inspect: each per
//     edgeconfig.WAFInspect (cdnca_waf.lua semantics).
//   - Header conditions read at most 100 request headers. More than 100:
//     HeaderOverflow "block" -> 403 before any policy; "no_match" -> a warning
//     is logged and header conditions see no headers.
//
// Port conditions exist because control compiles a policy once per listener
// (a "port" rule condition is resolved per port): rules of several ports may
// sit in one policy, each pinned to its port, and only the request's port can
// match them, so concatenating them keeps every port's result. A rule with
// port 0 applies to every port.
type RulePlan struct {
	HeaderOverflow string       `json:"header_overflow"`
	Policies       []RulePolicy `json:"policies"`
}

const (
	HeaderOverflowNoMatch = "no_match"
	HeaderOverflowBlock   = "block"
)

// RulePolicy is one bound security policy (edgeconfig.SecurityPolicy).
type RulePolicy struct {
	Kind            edgeconfig.SecurityKind `json:"kind"`
	PolicyID        string                  `json:"policy_id"`
	PolicyVersion   int64                   `json:"policy_version"`
	BindingRevision int64                   `json:"binding_revision"`
	RuntimeSHA256   string                  `json:"runtime_sha256"`
	Enabled         bool                    `json:"enabled"`
	DefaultAction   edgeconfig.WAFAction    `json:"default_action"`
	Rules           []edgeconfig.WAFRule    `json:"rules"`
	// Mode (observe) and AutoBlock: WAF v2 policy settings
	// (edgeconfig.SecurityPolicy); with challenge / ban rules they make the
	// node plan a segment action spec (edgeconfig.WAFActionSpecJSON).
	Mode      edgeconfig.WAFMode       `json:"mode,omitempty"`
	AutoBlock *edgeconfig.WAFAutoBlock `json:"auto_block,omitempty"`
}

func validateRulePlan(plan RulePlan, ports map[int]bool) error {
	if plan.HeaderOverflow != HeaderOverflowNoMatch && plan.HeaderOverflow != HeaderOverflowBlock ||
		plan.Policies == nil || len(plan.Policies) > MaxRulePolicies {
		return fmt.Errorf("%w: rule plan", ErrInvalid)
	}
	kinds := map[edgeconfig.SecurityKind]bool{}
	total := 0
	for _, policy := range plan.Policies {
		if policy.Kind != edgeconfig.SecurityACL && policy.Kind != edgeconfig.SecurityWAF || kinds[policy.Kind] ||
			!validUUID(policy.PolicyID) || !validRevision(policy.PolicyVersion) || !validRevision(policy.BindingRevision) ||
			!digestPattern.MatchString(policy.RuntimeSHA256) ||
			policy.DefaultAction != edgeconfig.WAFAllow && policy.DefaultAction != edgeconfig.WAFBlock || policy.Rules == nil {
			return fmt.Errorf("%w: rule policy", ErrInvalid)
		}
		if err := edgeconfig.ValidateSecurityPolicyWAFSettings(policy.Kind, policy.Mode, policy.AutoBlock); err != nil {
			return fmt.Errorf("%w: rule policy %s mode / auto_block", ErrInvalid, policy.PolicyID)
		}
		kinds[policy.Kind] = true
		total += len(policy.Rules)
		if total > MaxPlanRules {
			return fmt.Errorf("%w: more than %d rules", ErrInvalid, MaxPlanRules)
		}
		for _, rule := range policy.Rules {
			normalized, err := edgeconfig.NormalizeSecurityRule(rule)
			if err != nil {
				return fmt.Errorf("%w: rule %s: %v", ErrInvalid, rule.RuleID, err)
			}
			got, _ := json.Marshal(rule)
			want, _ := json.Marshal(normalized)
			if !bytes.Equal(got, want) {
				return fmt.Errorf("%w: rule %s is not normalized", ErrInvalid, rule.RuleID)
			}
			// challenge / ban (with their action_config) are WAF v2 actions.
			if policy.Kind != edgeconfig.SecurityWAF && (rule.Action == edgeconfig.WAFChallenge || rule.Action == edgeconfig.WAFBan) {
				return fmt.Errorf("%w: rule %s: %s is a WAF action", ErrInvalid, rule.RuleID, rule.Action)
			}
			if rule.Match.Port != 0 && !ports[int(rule.Match.Port)] {
				return fmt.Errorf("%w: rule %s names port %d the site does not serve", ErrInvalid, rule.RuleID, rule.Match.Port)
			}
		}
	}
	return nil
}
