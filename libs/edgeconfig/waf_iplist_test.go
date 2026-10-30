package edgeconfig

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const testIPListID = "0190a000-0000-7000-8000-000000000001"

func TestCanonicalIPListCIDRs(t *testing.T) {
	got, err := CanonicalIPListCIDRs([]string{" 192.0.2.9 ", "10.1.2.3/8", "2001:db8::1", "10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.9/32", "2001:db8::/32", "2001:db8::1/128"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, bad := range [][]string{nil, {}, {"x"}, {"::ffff:10.0.0.0/104"}, {"224.0.0.0/4"}} {
		if _, err := CanonicalIPListCIDRs(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func TestNormalizeWAFMatchIPLists(t *testing.T) {
	list := WAFIPList{ListID: testIPListID, Revision: 3, CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}}
	match, err := normalizeWAFMatch(WAFMatch{IPLists: []WAFIPList{list}})
	if err != nil || !reflect.DeepEqual(match.IPLists, []WAFIPList{list}) {
		t.Fatalf("%+v %v", match, err)
	}
	invalid := []WAFIPList{
		{ListID: "x", Revision: 1, CIDRs: []string{"10.0.0.0/8"}},
		{ListID: testIPListID, Revision: 0, CIDRs: []string{"10.0.0.0/8"}},
		{ListID: testIPListID, Revision: 1},
		{ListID: testIPListID, Revision: 1, CIDRs: []string{"10.1.0.0/8"}},                  // not masked
		{ListID: testIPListID, Revision: 1, CIDRs: []string{"2001:db8::/32", "10.0.0.0/8"}}, // not sorted
		{ListID: testIPListID, Revision: 1, CIDRs: []string{"10.0.0.0/8", "10.0.0.0/8"}},    // duplicate
	}
	for _, value := range invalid {
		if _, err := normalizeWAFMatch(WAFMatch{IPLists: []WAFIPList{value}}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%+v accepted", value)
		}
	}
	five := make([]WAFIPList, MaxWAFIPListsPerRule+1)
	for index := range five {
		five[index] = list
	}
	if _, err := normalizeWAFMatch(WAFMatch{IPLists: five}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("too many lists accepted")
	}
}

// The renderer and the rule plan carry the same spec, after ip_intel and
// before inspect (no request side effect before the list lookup).
func TestIPListConditionRenderAndPlan(t *testing.T) {
	list := WAFIPList{ListID: testIPListID, Revision: 2, CIDRs: []string{"192.0.2.0/24"}, Negate: true}
	spec := IPListConditionSpec(list)
	if spec != `{"id":"`+testIPListID+`","revision":2,"negate":true,"cidrs":["192.0.2.0/24"]}` {
		t.Fatalf("spec %s", spec)
	}
	rule := WAFRule{RuleID: "0190a000-0000-7000-8000-0000000000aa", Action: WAFBlock, Control: WAFContinue,
		Match: WAFMatch{Method: "GET", IPLists: []WAFIPList{list},
			Inspect: []WAFInspect{{Target: "path", Operator: "contains", Values: []string{"x"}}}}}
	rendered := renderBoundSecurityCondition(0, 0, 0, rule)
	if !strings.Contains(rendered, `require("cdnca_waf").ip_list([[`+spec+`]]) and require("cdnca_waf").inspect(`) {
		t.Fatalf("rendered %s", rendered)
	}
	conditions, err := rulePlanConditions(rule)
	if err != nil || len(conditions) != 3 || conditions[1].Op != RuleOpIPList || conditions[1].Value != spec ||
		conditions[2].Op != RuleOpInspect {
		t.Fatalf("plan %+v %v", conditions, err)
	}
	policy := SecurityPolicy{Rules: []WAFRule{rule}}
	if !SecurityPoliciesUseIPLists([]SecurityPolicy{policy}) ||
		ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{policy}}) != WAFConditionsAPIVersion {
		t.Fatal("IP lists need WAF v4")
	}
}
