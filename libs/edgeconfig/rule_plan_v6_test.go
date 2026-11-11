package edgeconfig

import (
	"errors"
	"strings"
	"testing"
)

// WAF v6 conditions in the rule plan: the order (client conditions after
// ja4_not_in, before ip_intel; string sets after ip_list, before inspect),
// the condition Spec as value, and the site's string sets
// carried as the plan's string_sets.
func TestRulePlanV6Conditions(t *testing.T) {
	timeMatch, err := CompileWAFTimeMatch("UTC", []string{"mon 09:00-10:00"}, false, timeWindowNow)
	if err != nil {
		t.Fatal(err)
	}
	ref := WAFStringSetRef{SetID: testStringSetID, Revision: 2, Target: StringSetTargetHeader, Key: "x-app", Negate: true}
	set := WAFStringSet{ID: testStringSetID, Revision: 2, Mode: StringSetPrefix, CaseSensitive: true, Members: []string{"/admin"}}
	match := WAFMatch{Method: "GET", NotJA4: []string{"t13d1516h2_8daaf6152771_b0da82dd1658"},
		Browser:        &WAFBrowserMatch{Names: []string{WAFBrowserChrome}},
		BrowserVersion: &WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionLT, Version: [3]int{100, 0, 0}},
		Device:         &WAFDeviceMatch{Kinds: []string{WAFDeviceBot}, Negate: true},
		Time:           &timeMatch,
		IPLists:        []WAFIPList{{ListID: testIPListID, Revision: 1, CIDRs: []string{"10.0.0.0/8"}}},
		StringSets:     []WAFStringSetRef{ref},
		Inspect:        []WAFInspect{{Target: "path", Operator: "contains", Values: []string{"x"}}}}
	policies := []SecurityPolicy{{Kind: SecurityWAF, PolicyID: planWAFPolicyID, PolicyVersion: 1, BindingRevision: 1,
		RuntimeSHA256: planSHA, Enabled: true, DefaultAction: WAFAllow,
		Rules: []WAFRule{{RuleID: planRuleB, Action: WAFBlock, Control: WAFStop, Match: match}}}}
	plan, err := CompileSiteSecurityRulePlan("", policies, []WAFStringSet{set}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	conditions := plan.Segments[0].Rules[0].Conditions
	wantOps := []string{RuleOpMethodEq, RuleOpJA4NotIn, RuleOpBrowserIn, RuleOpBrowserVersion, RuleOpDeviceIn,
		RuleOpTimeWindow, RuleOpIPList, RuleOpStringSet, RuleOpInspect}
	if len(conditions) != len(wantOps) {
		t.Fatalf("conditions %+v", conditions)
	}
	for index, op := range wantOps {
		if conditions[index].Op != op {
			t.Fatalf("condition %d op %s, want %s", index, conditions[index].Op, op)
		}
	}
	if got, want := conditions[7].Value, `{"id":"`+testStringSetID+`","revision":2,"target":"header","key":"x-app","negate":true}`; got != want {
		t.Fatalf("string_set value %s, want %s", got, want)
	}
	if got, want := conditions[2].Value, `{"names":["google_chrome"]}`; got != want {
		t.Fatalf("browser_in value %s", got)
	}
	if got, want := conditions[4].Value, `{"kinds":["bot"],"negate":true}`; got != want {
		t.Fatalf("device_in value %s", got)
	}
	if len(plan.StringSets) != 1 || plan.StringSets[0].ID != testStringSetID {
		t.Fatalf("plan string_sets %+v", plan.StringSets)
	}
	// A reference without its set (or at another revision) refuses the plan,
	// as the interpreter does.
	for name, sets := range map[string][]WAFStringSet{"missing": nil, "revision": {{ID: testStringSetID, Revision: 3,
		Mode: StringSetPrefix, CaseSensitive: true, Members: []string{"/admin"}}}} {
		if _, err := CompileSiteSecurityRulePlan("", policies, sets, false, true); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A plan without v6 conditions has no string_sets key (byte-identical plans).
func TestRulePlanWithoutStringSetsUnchanged(t *testing.T) {
	plan, err := CompileSecurityRulePlan(planPolicies(), true, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := EncodeRulePlan(plan)
	if plan.StringSets != nil || len(encoded) == 0 || strings.Contains(string(encoded), `"string_sets"`) {
		t.Fatalf("plan has string_sets: %s", encoded)
	}
}
