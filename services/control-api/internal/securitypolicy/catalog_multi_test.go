package securitypolicy

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

func seedCatalogIndex() map[string]rulecatalog.Item {
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CurrentSeed() {
		items[item.SystemKey] = item
	}
	return items
}

// TestExpandCCRuleGroupsMergesInOrder (#16): several system CC rule groups
// expand in the order chosen; priority is group order × 1000 + position;
// a rule another chosen group already contributed is dropped and reported,
// a same-match rule with a different action is kept and reported as a
// conflict (the earlier group's rule runs first).
func TestExpandCCRuleGroupsMergesInOrder(t *testing.T) {
	items := seedCatalogIndex()
	first, err := ExpandCCRuleGroup(items, "cc_rule:10001")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExpandCCRuleGroup(items, "cc_rule:6")
	if err != nil {
		t.Fatal(err)
	}
	merged, err := ExpandCCRuleGroups(items, []string{"cc_rule:10001", "cc_rule:6"})
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Rules) != len(first)+len(second) || len(merged.Duplicates) != 0 {
		t.Fatalf("merged %d rules (%d+%d), duplicates %v", len(merged.Rules), len(first), len(second), merged.Duplicates)
	}
	for index, rule := range merged.Rules {
		group, position := 1, index+1
		if index >= len(first) {
			group, position = 2, index-len(first)+1
		}
		if rule.Priority != group*1000+position || rule.Name == "" {
			t.Fatalf("rule %d priority %d, want %d", index, rule.Priority, group*1000+position)
		}
	}
	if err := ValidatePublishablePolicy(Policy{Kind: KindCC, Name: "merged", Enabled: true, DefaultAction: ActionAllow,
		Rules: merged.Rules}); err != nil {
		t.Fatalf("merged rules are not publishable: %v", err)
	}

	// The same group twice and an unknown or non-CC key are refused.
	for _, keys := range [][]string{{"cc_rule:6", "cc_rule:6"}, {"cc_rule:6", "missing"}, {}, {"waf_set:sqli"},
		{"cc_rule:1", "cc_rule:2", "cc_rule:3", "cc_rule:4", "cc_rule:5", "cc_rule:6", "cc_rule:7", "cc_rule:8", "cc_rule:9"}} {
		if _, err := ExpandCCRuleGroups(items, keys); !errors.Is(err, ErrCatalogUnsupported) && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("keys %v accepted: %v", keys, err)
		}
	}
}

func TestMergeCCRuleGroupsDeduplicatesAndReportsConflicts(t *testing.T) {
	rule := func(name, action string) Rule {
		result := Rule{Name: name, Priority: 1, Enabled: true, Flow: FlowStop,
			Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}}}
		if action == "ban" {
			result.Action, result.ActionConfig = ActionRateLimit, ActionConfig{RateLimit: &RateLimitConfig{Algorithm: "fixed_window",
				WindowSeconds: 10, MaxRequests: 30, ResponseAction: "temporary_ban", BanSeconds: 60}}
		} else {
			result.Action, result.ActionConfig = ActionRateLimit, ActionConfig{RateLimit: &RateLimitConfig{Algorithm: "fixed_window",
				WindowSeconds: 10, MaxRequests: 30, ResponseAction: "log"}}
			result.Flow = FlowContinue
		}
		return result
	}
	merged := mergeCCRuleGroups([]string{"g1", "g2"}, [][]Rule{
		{rule("a · ban", "ban")},
		{rule("b · ban", "ban"), rule("b · log", "log")},
	})
	if len(merged.Rules) != 2 || merged.Rules[0].Priority != 1001 || merged.Rules[1].Priority != 2002 {
		t.Fatalf("rules = %+v", merged.Rules)
	}
	if len(merged.Duplicates) != 1 || merged.Duplicates[0].GroupKey != "g2" || merged.Duplicates[0].SameAs != "g1" ||
		merged.Duplicates[0].Rule != "b · ban" {
		t.Fatalf("duplicates = %+v", merged.Duplicates)
	}
	if len(merged.Conflicts) != 1 || merged.Conflicts[0].GroupKey != "g2" || merged.Conflicts[0].With != "g1" ||
		merged.Conflicts[0].Rule != "b · log" {
		t.Fatalf("conflicts = %+v", merged.Conflicts)
	}
}
