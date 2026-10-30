package securitypublication

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	overrideNodeA = uuid.MustParse("018f1000-0000-7000-8000-0000000000a1")
	overrideNodeB = uuid.MustParse("018f1000-0000-7000-8000-0000000000b1")
	overrideNodeC = uuid.MustParse("018f1000-0000-7000-8000-0000000000c1")
)

// overridePolicyForTest is autoSwitchPolicyForTest following the system
// with three overrides: node A off, node B at 50 QPS on the global group,
// node C at 80 QPS on another group (one rule set).
func overridePolicyForTest() securitypolicy.Policy {
	policy := autoSwitchPolicyForTest()
	value := policy.CCSettings.AutoSwitch
	value.Mode = securitypolicy.CCSettingSystem
	other := value.Rules[0]
	other.ID = uuid.Nil
	other.Name = "other"
	value.Overrides = []securitypolicy.CCAutoSwitchOverride{
		{Nodes: []uuid.UUID{overrideNodeC}, QPSTotal: 80, RecoverSeconds: 120, RuleGroup: "cc_rule:2"},
		{Nodes: []uuid.UUID{overrideNodeA}},
		{Nodes: []uuid.UUID{overrideNodeB}, QPSTotal: 50, RecoverSeconds: 300, RuleGroup: "cc_rule:1"},
	}
	value.RuleSets = []securitypolicy.CCAutoSwitchRuleSet{{Group: "cc_rule:2", Rules: []securitypolicy.Rule{other}}}
	canonical, err := securitypolicy.CanonicalCCSettings(policy.ID, policy.CCSettings)
	if err != nil {
		panic(err)
	}
	policy.CCSettings = canonical
	return policy
}

func TestCompileCCV2AutoSwitchOverrides(t *testing.T) {
	_, compiled, policy := compileAutoSwitchFixture(t, overridePolicyForTest())
	value := policy.AutoSwitch
	if value == nil || value.QPSTotal != 200 || len(value.Rules) != 1 || len(value.Overrides) != 3 || len(value.RuleSets) != 1 {
		t.Fatalf("auto switch = %+v", value)
	}
	if got := edgeconfig.CCV2PolicyAPIVersion(policy); got != edgeconfig.CCAutoSwitchOverridesAPIVersion {
		t.Fatalf("API version = %d", got)
	}
	want := []edgeconfig.CCV2AutoSwitchOverride{
		{Nodes: []string{overrideNodeA.String()}},
		{Nodes: []string{overrideNodeB.String()}, QPSTotal: 50, RecoverSeconds: 300},
		{Nodes: []string{overrideNodeC.String()}, QPSTotal: 80, RecoverSeconds: 120, RuleSet: "cc_rule:2"},
	}
	for index, override := range value.Overrides {
		if strings.Join(override.Nodes, ",") != strings.Join(want[index].Nodes, ",") || override.QPSTotal != want[index].QPSTotal ||
			override.RecoverSeconds != want[index].RecoverSeconds || override.RuleSet != want[index].RuleSet {
			t.Fatalf("override %d = %+v, want %+v", index, override, want[index])
		}
	}
	if value.RuleSets[0].Name != "cc_rule:2" || value.RuleSets[0].Rules[0].RuleID == value.Rules[0].RuleID {
		t.Fatalf("rule set = %+v", value.RuleSets[0])
	}
	// The site duration applies to rule set rules too.
	if !strings.Contains(string(compiled), `"rule_sets":[{"name":"cc_rule:2","rules":[`) ||
		strings.Count(string(compiled), `"pass_seconds":7200`) != 2 {
		t.Fatalf("compiled = %s", compiled)
	}
	if _, err := edgeconfig.DecodeCCV2Policy(compiled); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestCompileCCV2AutoSwitchOverridesGlobalOff(t *testing.T) {
	policy := overridePolicyForTest()
	value := policy.CCSettings.AutoSwitch
	value.QPSTotal, value.QPS5xx, value.RecoverSeconds, value.RuleGroups, value.Rules = 0, 0, 0, []string{}, []securitypolicy.Rule{}
	// With global off, node B's override on the old global group needs a rule set of its own.
	value.Overrides = []securitypolicy.CCAutoSwitchOverride{
		{Nodes: []uuid.UUID{overrideNodeC}, QPSTotal: 80, RecoverSeconds: 120, RuleGroup: "cc_rule:2"}}
	canonical, err := securitypolicy.CanonicalCCSettings(policy.ID, policy.CCSettings)
	if err != nil {
		t.Fatal(err)
	}
	policy.CCSettings = canonical
	_, _, compiled := compileAutoSwitchFixture(t, policy)
	got := compiled.AutoSwitch
	if got == nil || got.QPSTotal != 0 || len(got.Rules) != 0 || len(got.Overrides) != 1 ||
		got.Overrides[0].RuleSet != "cc_rule:2" || got.Overrides[0].Nodes[0] != overrideNodeC.String() {
		t.Fatalf("auto switch = %+v", got)
	}
}

func TestCCV2AutoSwitchOverridesValidation(t *testing.T) {
	_, _, policy := compileAutoSwitchFixture(t, overridePolicyForTest())
	for name, mutate := range map[string]func(*edgeconfig.CCV2AutoSwitch){
		"node in two overrides":  func(value *edgeconfig.CCV2AutoSwitch) { value.Overrides[1].Nodes = value.Overrides[0].Nodes },
		"unknown rule set":       func(value *edgeconfig.CCV2AutoSwitch) { value.Overrides[2].RuleSet = "cc_rule:9" },
		"unused rule set":        func(value *edgeconfig.CCV2AutoSwitch) { value.Overrides[2].RuleSet = "" },
		"off with recovery":      func(value *edgeconfig.CCV2AutoSwitch) { value.Overrides[0].RecoverSeconds = 60 },
		"recovery out of range":  func(value *edgeconfig.CCV2AutoSwitch) { value.Overrides[1].RecoverSeconds = 30 },
		"rule set without nodes": func(value *edgeconfig.CCV2AutoSwitch) { value.Overrides = nil },
	} {
		t.Run(name, func(t *testing.T) {
			copied := policy
			value := *policy.AutoSwitch
			value.Overrides = append([]edgeconfig.CCV2AutoSwitchOverride(nil), policy.AutoSwitch.Overrides...)
			copied.AutoSwitch = &value
			mutate(&value)
			if _, err := edgeconfig.CanonicalCCV2Policy(copied); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestResolveCCSettingsNodeOverrides(t *testing.T) {
	policy := overridePolicyForTest()
	catalog := testCCCatalog(t)
	settings := &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingSystem,
		RuleGroups: []string{}, Rules: []securitypolicy.Rule{}}}
	global := securitypolicy.CCSystemAutoSwitch{Enable: true, QPSTotal: 1000, Rule: catalogGroup(t, catalog, 0), Seconds: 300}
	other := securitypolicy.CCSystemAutoSwitch{Enable: true, QPSTotal: 80, Rule: catalogGroup(t, catalog, 1), Seconds: 120}
	layers := securitypolicy.AutoSwitchLayers{Global: global, Nodes: securitypolicy.ResolveAutoSwitchLayers(global,
		map[string]securitypolicy.CCSystemAutoSwitch{"east": other}, map[uuid.UUID]securitypolicy.CCSystemAutoSwitch{overrideNodeA: {}},
		[]securitypolicy.PlatformNode{{ID: overrideNodeA, Region: "east"}, {ID: overrideNodeB, Region: "east"}, {ID: overrideNodeC, Region: "west"}})}
	securitypolicy.ResolveCCSettings(settings, securitypolicy.CCSystemDefaults{AutoSwitch: global, Layers: layers}, catalog)
	value := settings.AutoSwitch
	if !value.Active() || value.QPSTotal != 1000 || len(value.Overrides) != 2 || len(value.RuleSets) != 1 {
		t.Fatalf("resolved = %+v", value)
	}
	if value.Overrides[0].Nodes[0] != overrideNodeA || value.Overrides[0].RuleGroup != "" ||
		value.Overrides[1].Nodes[0] != overrideNodeB || value.Overrides[1].QPSTotal != 80 || value.Overrides[1].RuleGroup != other.Rule {
		t.Fatalf("overrides = %+v", value.Overrides)
	}
	if _, err := securitypolicy.CanonicalCCSettings(policy.ID, settings); err != nil {
		t.Fatalf("resolved settings are not canonical: %v", err)
	}
	// Q3: a custom switch is never overridden.
	custom := &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom}}
	securitypolicy.ResolveCCSettings(custom, securitypolicy.CCSystemDefaults{AutoSwitch: global, Layers: layers}, catalog)
	if len(custom.AutoSwitch.Overrides) != 0 {
		t.Fatalf("custom switch got overrides: %+v", custom.AutoSwitch)
	}
}

func testCCCatalog(t *testing.T) []rulecatalog.Item {
	t.Helper()
	return rulecatalog.CurrentSeed()
}

// catalogGroup is the n-th CC rule group of the seed that expands to rules.
func catalogGroup(t *testing.T, catalog []rulecatalog.Item, n int) string {
	t.Helper()
	index := map[string]rulecatalog.Item{}
	for _, item := range catalog {
		index[item.SystemKey] = item
	}
	for _, item := range catalog {
		if item.Kind != rulecatalog.KindCCRuleGroup {
			continue
		}
		if rules, err := securitypolicy.ExpandCCRuleGroup(index, item.SystemKey); err == nil && len(rules) > 0 {
			if n == 0 {
				return item.SystemKey
			}
			n--
		}
	}
	t.Fatal("seed has too few CC rule groups")
	return ""
}
