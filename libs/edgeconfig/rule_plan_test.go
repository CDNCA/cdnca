package edgeconfig

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	planACLPolicyID = "11111111-1111-4111-8111-111111111111"
	planWAFPolicyID = "22222222-2222-4222-8222-222222222222"
	planRuleA       = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	planRuleB       = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	planRuleC       = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	planSHA         = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func planPolicies() []SecurityPolicy {
	return []SecurityPolicy{
		{Kind: SecurityWAF, PolicyID: planWAFPolicyID, PolicyVersion: 3, BindingRevision: 2, RuntimeSHA256: strings.ToUpper(planSHA),
			Enabled: true, DefaultAction: WAFAllow, Rules: []WAFRule{
				{RuleID: planRuleB, Action: WAFBlock, Control: WAFStop, Match: WAFMatch{
					Host: "Example.COM", Port: 443, Method: "post", Path: &WAFPathMatch{Kind: WAFPathPrefix, Value: "/api"},
					Header:  &WAFHeaderMatch{Name: "X-Token", Kind: WAFHeaderExact, Value: "abc"},
					JA4:     []string{"t13d1516h2_8daaf6152771_b0da82dd1658"},
					IPIntel: []WAFIPIntel{{Field: WAFIPIntelTag, Values: []string{"idc:cn", "carrier:cn-telecom"}}},
					Inspect: []WAFInspect{{Target: "args", Operator: "contains", Values: []string{"<script"}}},
				}},
				{RuleID: planRuleC, Action: WAFLog, Control: WAFContinue, Match: WAFMatch{
					Path: &WAFPathMatch{Kind: WAFPathRawPrefix, Value: "/raw"}, Header: &WAFHeaderMatch{Name: "x-a", Kind: WAFHeaderExists}}},
			}},
		{Kind: SecurityACL, PolicyID: planACLPolicyID, PolicyVersion: 1, BindingRevision: 1, RuntimeSHA256: planSHA,
			Enabled: true, DefaultAction: WAFBlock, Rules: []WAFRule{
				{RuleID: planRuleA, Action: WAFAllow, Control: WAFStop, Comment: "office", ExpiresAt: "2030-01-02T03:04:05Z",
					Match: WAFMatch{SourceCIDR: "2001:DB8::/32"}},
			}},
	}
}

// The IR is the compiled form the interpreter executes; this golden pins its
// field names, order and the normalization it shares with the renderer.
func TestCompileSecurityRulePlanGolden(t *testing.T) {
	plan, err := CompileSecurityRulePlan(planPolicies(), true, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRulePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"cdnca.edge.rule-plan/v1","header_overflow":"block","telemetry":true,"segments":[` +
		`{"kind":"acl","policy_id":"` + planACLPolicyID + `","policy_version":1,"binding_revision":1,"runtime_sha256":"` + planSHA + `","enabled":true,"default_action":"block","default_rule_id":"` + planACLPolicyID + `:default","rules":[` +
		`{"rule_id":"` + planRuleA + `","action":"allow","flow":"stop","conditions":[{"op":"expires_before","number":1893553445},{"op":"source_cidr","value":"2001:db8::/32"}]}]},` +
		`{"kind":"waf","policy_id":"` + planWAFPolicyID + `","policy_version":3,"binding_revision":2,"runtime_sha256":"` + planSHA + `","enabled":true,"default_action":"allow","default_rule_id":"` + planWAFPolicyID + `:default","rules":[` +
		`{"rule_id":"` + planRuleB + `","action":"block","flow":"stop","conditions":[{"op":"host_eq","value":"example.com"},{"op":"port_eq","number":443},{"op":"method_eq","value":"POST"},{"op":"path_prefix","value":"/api"},{"op":"header_eq","name":"x-token","value":"abc"},{"op":"ja4_in","values":["t13d1516h2_8daaf6152771_b0da82dd1658"]},{"op":"ip_intel","value":"tag=0000000000010001"},{"op":"inspect","value":"{\"target\":\"args\",\"operator\":\"contains\",\"values\":[\"\\u003cscript\"]}"}]},` +
		`{"rule_id":"` + planRuleC + `","action":"log","flow":"continue","conditions":[{"op":"path_raw_prefix","value":"/raw"},{"op":"header_exists","name":"x-a"}]}]}]}`
	if string(encoded) != want {
		t.Fatalf("plan JSON\n got %s\nwant %s", encoded, want)
	}
	again, _ := CompileSecurityRulePlan(planPolicies(), true, true)
	second, _ := EncodeRulePlan(again)
	if string(second) != string(encoded) {
		t.Fatal("plan encoding is not deterministic")
	}
}

// The inspect payload must be the exact bytes the renderer embeds: the
// cdnca_waf inspect cache is keyed by them.
func TestRulePlanInspectMatchesRenderedCondition(t *testing.T) {
	plan, err := CompileSecurityRulePlan(planPolicies(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	inspect := plan.Segments[1].Rules[0].Conditions[7]
	rendered := RenderWAFInspectCondition(planPolicies()[0].Rules[0].Match.Inspect[0])
	if !strings.Contains(rendered, "["+inspect.Value+"]") {
		t.Fatalf("inspect %q not embedded verbatim in %s", inspect.Value, rendered)
	}
	if plan.HeaderOverflow != RulePlanHeaderNoMatch || plan.Telemetry {
		t.Fatalf("header_overflow=%s telemetry=%v", plan.HeaderOverflow, plan.Telemetry)
	}
}

func TestCompileSecurityRulePlanEdgeCases(t *testing.T) {
	plan, err := CompileSecurityRulePlan(nil, true, true)
	if err != nil || len(plan.Segments) != 0 || plan.HeaderOverflow != RulePlanHeaderNone {
		t.Fatalf("empty plan = %+v, %v", plan, err)
	}
	encoded, _ := EncodeRulePlan(plan)
	if string(encoded) != `{"schema":"cdnca.edge.rule-plan/v1","header_overflow":"none","telemetry":true,"segments":[]}` {
		t.Fatalf("empty plan JSON %s", encoded)
	}
	// A disabled policy runs no rules but keeps its default action, and its
	// header rules still make the request headers read (renderWAFBlock counts
	// every policy's rules).
	policies := planPolicies()[:1]
	policies[0].Enabled = false
	plan, err = CompileSecurityRulePlan(policies, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if segment := plan.Segments[0]; segment.Enabled || len(segment.Rules) != 0 || segment.DefaultAction != WAFAllow ||
		plan.HeaderOverflow != RulePlanHeaderBlock {
		t.Fatalf("disabled segment = %+v header_overflow=%s", segment, plan.HeaderOverflow)
	}
	// Epoch zero is a real expiry, not an absent number.
	policies = []SecurityPolicy{{Kind: SecurityACL, PolicyID: planACLPolicyID, PolicyVersion: 1, BindingRevision: 1, RuntimeSHA256: planSHA,
		Enabled: true, DefaultAction: WAFAllow, Rules: []WAFRule{{RuleID: planRuleA, Action: WAFBlock, Control: WAFStop,
			ExpiresAt: "1970-01-01T00:00:00Z", Match: WAFMatch{SourceCIDR: "10.0.0.0/8"}}}}}
	plan, err = CompileSecurityRulePlan(policies, false, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = EncodeRulePlan(plan)
	if !strings.Contains(string(encoded), `{"op":"expires_before","number":0}`) {
		t.Fatalf("epoch expiry lost: %s", encoded)
	}
}

func TestCompileSecurityRulePlanRejectsWhatTheRendererRejects(t *testing.T) {
	for name, mutate := range map[string]func([]SecurityPolicy) []SecurityPolicy{
		"duplicate kind": func(p []SecurityPolicy) []SecurityPolicy { p[1].Kind = SecurityWAF; return p },
		"bad rule id":    func(p []SecurityPolicy) []SecurityPolicy { p[0].Rules[0].RuleID = "r1"; return p },
		"empty match":    func(p []SecurityPolicy) []SecurityPolicy { p[0].Rules[1].Match = WAFMatch{}; return p },
		"three policies": func(p []SecurityPolicy) []SecurityPolicy { return append(p, p[0]) },
	} {
		if _, err := CompileSecurityRulePlan(mutate(planPolicies()), false, false); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestCompileLayeredRulePlanOrdersLayers(t *testing.T) {
	policies := planPolicies()
	segments := []RulePlanSegmentInput{
		{Layer: RulePlanLayerUser, Policy: policies[1]},
		{Layer: RulePlanLayerDeveloper, Policy: policies[0]},
		{Layer: RulePlanLayerSystem, Policy: policies[0]},
	}
	plan, err := CompileLayeredRulePlan(segments, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Segments) != 3 || plan.Segments[0].Layer != RulePlanLayerUser || plan.Segments[2].Layer != RulePlanLayerSystem {
		t.Fatalf("segments = %+v", plan.Segments)
	}
	for name, input := range map[string][]RulePlanSegmentInput{
		"system before user": {segments[2], segments[0]},
		"unknown layer":      {{Layer: "tenant", Policy: policies[0]}},
		"no layer":           {{Policy: policies[0]}},
	} {
		if _, err := CompileLayeredRulePlan(input, false, true); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A layered plan is not bound by the two-policy / 128-rule bound-policy
	// limits, only by the plan limits.
	big := policies[0]
	big.Rules = nil
	for index := 0; index < 1000; index++ {
		big.Rules = append(big.Rules, WAFRule{RuleID: planRuleC, Action: WAFLog, Control: WAFContinue,
			Match: WAFMatch{Path: &WAFPathMatch{Kind: WAFPathExact, Value: "/x"}}})
	}
	if _, err := CompileLayeredRulePlan([]RulePlanSegmentInput{{Layer: RulePlanLayerSystem, Policy: big}}, false, false); err != nil {
		t.Fatalf("1000-rule segment: %v", err)
	}
	for len(big.Rules) <= MaxRulePlanRules {
		big.Rules = append(big.Rules, big.Rules[0])
	}
	if _, err := CompileLayeredRulePlan([]RulePlanSegmentInput{{Layer: RulePlanLayerSystem, Policy: big}}, false, false); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("over the plan rule limit: %v", err)
	}
}

func TestRulePlanJSONRoundTrip(t *testing.T) {
	plan, _ := CompileSecurityRulePlan(planPolicies(), true, true)
	encoded, _ := EncodeRulePlan(plan)
	var decoded RulePlan
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	again, _ := EncodeRulePlan(decoded)
	if string(again) != string(encoded) {
		t.Fatalf("round trip changed the plan\n%s\n%s", encoded, again)
	}
}
