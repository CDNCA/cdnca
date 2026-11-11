package edgeconfig

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// v6Matches are one match per new WAF v6 field (string sets, browser /
// browser version / device / request time).
func v6Matches() map[string]WAFMatch {
	timeMatch, _ := CompileWAFTimeMatch("UTC", []string{"mon 09:00-10:00"}, false, timeWindowNow)
	return map[string]WAFMatch{
		"string_sets":     {StringSets: []WAFStringSetRef{{SetID: testStringSetID, Revision: 1, Target: StringSetTargetUserAgent}}},
		"browser":         {Browser: &WAFBrowserMatch{Names: []string{WAFBrowserChrome}}},
		"browser_version": {BrowserVersion: &WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionLT, Version: [3]int{100, 0, 0}}},
		"device":          {Device: &WAFDeviceMatch{Kinds: []string{WAFDeviceBot}}},
		"time":            {Time: &timeMatch},
	}
}

// String sets and client conditions share one WAF version: v6. The node Lua
// implements it, so the agent advertises v6.
func TestWAFV6Version(t *testing.T) {
	if WAFStringSetAPIVersion != 6 || WAFClientConditionsAPIVersion != 6 {
		t.Fatalf("v6 constants %d %d", WAFStringSetAPIVersion, WAFClientConditionsAPIVersion)
	}
	if WAFNodeAPIVersion != WAFStringSetAPIVersion {
		t.Fatalf("node advertises WAF v%d, want v6", WAFNodeAPIVersion)
	}
	for name, match := range v6Matches() {
		normalized, err := normalizeWAFMatch(match)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !WAFMatchUsesV6Conditions(normalized) {
			t.Errorf("%s not a v6 condition", name)
		}
		policy := SecurityPolicy{Kind: SecurityWAF, Rules: []WAFRule{{RuleID: "0190a000-0000-7000-8000-0000000000aa", Action: WAFBlock, Control: WAFContinue, Match: normalized}}}
		if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{policy}}); got != WAFStringSetAPIVersion {
			t.Errorf("%s: WAF API version %d", name, got)
		}
		// v6 wins over the multipart v5 condition in the same release.
		policy.Rules = append(policy.Rules, WAFRule{RuleID: "0190a000-0000-7000-8000-0000000000ab", Action: WAFBlock, Control: WAFContinue,
			Match: WAFMatch{Inspect: []WAFInspect{{Target: "multipart_part_count", Operator: "gt", Values: []string{"10"}}}}})
		if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{policy}}); got != WAFStringSetAPIVersion {
			t.Errorf("%s with multipart: WAF API version %d", name, got)
		}
	}
	if WAFMatchUsesV6Conditions(WAFMatch{Method: "GET", IPLists: []WAFIPList{{ListID: testIPListID, Revision: 1, CIDRs: []string{"10.0.0.0/8"}}}}) {
		t.Fatal("v4 match reported as v6")
	}
}

// A rule without the new fields encodes exactly as before: every new field
// is omitted (no byte change in rule plans, site objects or documents).
func TestWAFMatchWithoutV6FieldsEncodesUnchanged(t *testing.T) {
	rule := WAFRule{RuleID: "0190a000-0000-7000-8000-0000000000aa", Action: WAFBlock, Control: WAFContinue,
		Match: WAFMatch{Method: "GET", JA4: []string{"t13d1516h2_8daaf6152771_02713d6af862"},
			Inspect: []WAFInspect{{Target: "user_agent", Operator: "contains", Values: []string{"bot"}}}}}
	normalized, err := normalizeSecurityRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(normalized.Match)
	const want = `{"method":"GET","inspect":[{"target":"user_agent","operator":"contains","values":["bot"]}],"ja4":["t13d1516h2_8daaf6152771_02713d6af862"]}`
	if string(raw) != want {
		t.Fatalf("match encoding changed:\n got %s\nwant %s", raw, want)
	}
	for _, field := range []string{"string_sets", "browser", "browser_version", "device", "time"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Fatalf("%s present", field)
		}
	}
}

// The legacy site WAF renderer has none of the v6 conditions; dropping one
// would widen the rule to every request, so a legacy policy refuses them.
func TestLegacyWAFPolicyRefusesV6Conditions(t *testing.T) {
	for name, match := range v6Matches() {
		policy := WAFPolicy{DefaultAction: WAFAllow, Rules: []WAFRule{{Match: match, Action: WAFDeny, Control: WAFStop}}}
		if _, err := normalizeWAF(policy); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s accepted by the legacy WAF policy: %v", name, err)
		}
	}
}

// A previous stop rule with a v6 condition does not cover a later rule:
// coverage is only claimed for the conditions it can compare.
func TestWAFMatchCoversIgnoresNothingNew(t *testing.T) {
	for name, match := range v6Matches() {
		if wafMatchCovers(match, WAFMatch{Method: "GET"}) {
			t.Errorf("%s covers every GET", name)
		}
	}
}
