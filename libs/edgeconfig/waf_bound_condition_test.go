package edgeconfig

import (
	"strings"
	"testing"
)

const boundConditionRuleID = "0190a000-0000-7000-8000-0000000000bb"

func boundConditionRule(match WAFMatch) WAFRule {
	return WAFRule{RuleID: boundConditionRuleID, Action: WAFBlock, Control: WAFContinue, Match: match}
}

// assertRenderedInOrder checks that every fragment is in the rendered
// condition, in the given order.
func assertRenderedInOrder(t *testing.T, rendered string, fragments []string) {
	t.Helper()
	offset := 0
	for _, fragment := range fragments {
		index := strings.Index(rendered[offset:], fragment)
		if index < 0 {
			t.Fatalf("missing or out of order %q in %s", fragment, rendered)
		}
		offset += index + len(fragment)
	}
}

func TestRenderBoundSecurityConditionV4Only(t *testing.T) {
	rule := boundConditionRule(WAFMatch{Host: "example.com", Method: "GET",
		Path: &WAFPathMatch{Kind: WAFPathExact, Value: "/admin"}})
	rendered := renderBoundSecurityCondition(0, 0, 0, rule)
	if rendered != `(ngx.var.host == "example.com" and method == "GET" and uri == "/admin")` {
		t.Fatalf("rendered %s", rendered)
	}
	if strings.Contains(rendered, `require("cdnca_waf")`) {
		t.Fatalf("v4 rule renders a v6 call: %s", rendered)
	}
}

func TestRenderBoundSecurityConditionV6(t *testing.T) {
	match := WAFMatch{
		Browser:        &WAFBrowserMatch{Names: []string{"chrome"}},
		BrowserVersion: &WAFBrowserVersion{Name: "chrome", Op: "lt", Version: [3]int{100, 0, 0}},
		Device:         &WAFDeviceMatch{Kinds: []string{"mobile"}, Negate: true},
		Time:           &WAFTimeMatch{Until: 1893456000},
		StringSets:     []WAFStringSetRef{{SetID: "0190a000-0000-7000-8000-0000000000cc", Revision: 3, Target: "user_agent"}},
	}
	rule := boundConditionRule(match)
	rendered := renderBoundSecurityCondition(0, 0, 0, rule)
	call := func(op, spec string) string { return `require("cdnca_waf").` + op + `([[` + spec + `]])` }
	assertRenderedInOrder(t, rendered, []string{
		call(RuleOpBrowserIn, match.Browser.Spec()),
		call(RuleOpBrowserVersion, match.BrowserVersion.Spec()),
		call(RuleOpDeviceIn, match.Device.Spec()),
		call(RuleOpTimeWindow, match.Time.Spec()),
		call(RuleOpStringSet, StringSetConditionSpec(match.StringSets[0])),
	})
	assertBoundConditionMatchesPlan(t, rule, rendered)
}

func TestRenderBoundSecurityConditionMixed(t *testing.T) {
	list := WAFIPList{ListID: testIPListID, Revision: 2, CIDRs: []string{"192.0.2.0/24"}}
	match := WAFMatch{
		Host: "example.com", Port: 443, Method: "POST",
		Path:       &WAFPathMatch{Kind: WAFPathPrefix, Value: "/api"},
		JA4:        []string{"t13d1516h2_8daaf6152771_b186095e22b6"},
		Browser:    &WAFBrowserMatch{Names: []string{"firefox"}, Negate: true},
		IPLists:    []WAFIPList{list},
		StringSets: []WAFStringSetRef{{SetID: "0190a000-0000-7000-8000-0000000000cc", Revision: 1, Target: "path", Negate: true}},
		Inspect:    []WAFInspect{{Target: "path", Operator: "contains", Values: []string{"x"}}},
	}
	rule := boundConditionRule(match)
	rendered := renderBoundSecurityCondition(0, 0, 0, rule)
	assertRenderedInOrder(t, rendered, []string{
		`ngx.var.host == "example.com"`,
		`tonumber(ngx.var.server_port) == 443`,
		`method == "POST"`,
		`uri == "/api"`,
		`require("cdnca_waf").` + RuleOpBrowserIn + `(`,
		`.` + ipListLuaFunction + `(`,
		`require("cdnca_waf").` + RuleOpStringSet + `(`,
		`require("cdnca_waf").inspect(`,
	})
	assertBoundConditionMatchesPlan(t, rule, rendered)
}

// assertBoundConditionMatchesPlan: the renderer and the rule plan emit the
// same number of conditions (each is joined by " and ").
func assertBoundConditionMatchesPlan(t *testing.T, rule WAFRule, rendered string) {
	t.Helper()
	conditions, err := rulePlanConditions(rule)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(rendered, " and "); got != len(conditions)-1 {
		t.Fatalf("renderer has %d conditions, plan %d: %s", got+1, len(conditions), rendered)
	}
}
