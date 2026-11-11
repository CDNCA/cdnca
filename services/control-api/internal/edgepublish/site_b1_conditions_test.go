package edgepublish

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// a string set condition compiles to (id, revision, target); an
// unresolved set or a ja4 condition on a non-JA4 set refuses the rule.
func TestCompileSecurityRuleStringSetCondition(t *testing.T) {
	setID := uuid.MustParse("0190a000-0000-7000-8000-0000000000c7")
	sets := securitypolicy.ResolvedStringSets{setID: {ID: setID.String(), Revision: 3, Mode: edgeconfig.StringSetContains,
		Members: []string{"sqlmap"}}}
	conditions := []securitypolicy.Condition{
		{Field: "user_agent", Operator: "in_string_set", Values: []string{setID.String()}},
		{Field: "header", Key: "x-client", Operator: "not_in_string_set", Values: []string{setID.String()}},
	}
	matches, err := compileSecurityRuleMatchesFor([]string{"a.example.test"}, 80, conditions, nil, sets)
	if err != nil || len(matches) != 1 || len(matches[0].StringSets) != 2 {
		t.Fatalf("%+v %v", matches, err)
	}
	header := matches[0].StringSets[1]
	if header.Target != "header" || header.Key != "x-client" || !header.Negate || header.Revision != 3 {
		t.Fatalf("header ref %+v", header)
	}
	if !edgeconfig.WAFMatchUsesV6Conditions(matches[0]) {
		t.Fatal("string set must require WAF v6")
	}
	if _, err := compileSecurityRuleMatchesFor([]string{"a.example.test"}, 80, conditions, nil, nil); !errors.Is(err, ErrUnsupportedSecurityPolicy) {
		t.Fatalf("unresolved set: %v", err)
	}
	ja4 := []securitypolicy.Condition{{Field: "ja4", Operator: "in_string_set", Values: []string{setID.String()}}}
	if _, err := compileSecurityRuleMatchesFor([]string{"a.example.test"}, 80, ja4, nil, sets); !errors.Is(err, ErrUnsupportedSecurityPolicy) {
		t.Fatalf("ja4 on a contains set: %v", err)
	}
}

// browser / device / version / time compile to the WAFMatch
// fields; the weekly offset table is anchored on securityRuleNow.
func TestCompileSecurityRuleClientConditions(t *testing.T) {
	previous := securityRuleNow
	securityRuleNow = func() time.Time { return time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { securityRuleNow = previous })
	conditions := []securitypolicy.Condition{
		{Field: "browser", Operator: "not_in", Values: []string{"microsoft_edge", "google_chrome"}},
		{Field: "browser_version", Key: "google_chrome", Operator: "version_lt", Values: []string{"100.1"}},
		{Field: "device", Operator: "in", Values: []string{"mobile"}},
		{Field: "request_time", Key: "Asia/Shanghai", Operator: "in_time_range", Values: []string{"mon,fri 09:00-18:00"}},
	}
	matches, err := compileSecurityRuleMatchesFor([]string{"a.example.test"}, 80, conditions, nil, nil)
	if err != nil || len(matches) != 1 {
		t.Fatalf("%+v %v", matches, err)
	}
	match := matches[0]
	if match.Browser == nil || !match.Browser.Negate || match.Browser.Names[0] != "google_chrome" ||
		match.BrowserVersion == nil || match.BrowserVersion.Op != edgeconfig.WAFVersionLT || match.BrowserVersion.Version != [3]int{100, 1, 0} ||
		match.Device == nil || match.Device.Kinds[0] != "mobile" || match.Time == nil || len(match.Time.Weekly) != 1 || len(match.Time.Offsets) == 0 {
		t.Fatalf("match %+v", match)
	}
	if _, err := edgeconfig.NormalizeSecurityRule(edgeconfig.WAFRule{RuleID: "0190a000-0000-7000-8000-0000000000d1", Match: match, Action: edgeconfig.WAFBlock,
		Control: edgeconfig.WAFStop}); err != nil {
		t.Fatalf("node normalization refused the compiled match: %v", err)
	}
	again, _ := compileSecurityRuleMatchesFor([]string{"a.example.test"}, 80, conditions, nil, nil)
	if again[0].Time.Spec() != match.Time.Spec() {
		t.Fatal("the time condition must compile the same way twice")
	}
}
