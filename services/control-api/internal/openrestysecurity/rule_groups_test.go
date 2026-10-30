package openrestysecurity

import (
	"reflect"
	"testing"
)

func TestRuleGroupReferenceScopeForPlatformAggregatesTenants(t *testing.T) {
	if got := ruleGroupReferenceScope(ScopePlatform); got != "(scope_id=$1 OR scope_id IN (SELECT id FROM access_scopes WHERE kind='tenant'))" {
		t.Fatalf("platform reference scope = %q", got)
	}
	if got := ruleGroupReferenceScope(ScopeTenant); got != "scope_id=$1" {
		t.Fatalf("tenant reference scope = %q", got)
	}
}

func TestMergeRuleGroupsKeepsMaterializedSystemOrderAndAppendsCustom(t *testing.T) {
	system := []RuleGroup{
		{ID: "10002", Name: "关闭", Enabled: true, Kind: "system", SystemRule: true, Sort: 1},
		{ID: "6", Name: "宽松", Enabled: true, Kind: "system", SystemRule: true, Sort: 2},
		{ID: "1", Name: "JS验证", Enabled: true, Kind: "system", SystemRule: true, Sort: 3},
		{ID: "10001", Name: "5秒盾", Enabled: true, Kind: "system", SystemRule: true, Sort: 4},
		{ID: "10000", Name: "点击验证", Enabled: true, Kind: "system", SystemRule: true, Sort: 5},
		{ID: "2", Name: "滑块验证", Enabled: true, Kind: "system", SystemRule: true, Sort: 6},
		{ID: "4", Name: "验证码", Enabled: true, Kind: "system", SystemRule: true, Sort: 7},
		{ID: "10003", Name: "旋转图片", Enabled: true, Kind: "system", SystemRule: true, Sort: 8},
		{ID: "10004", Name: "点击验证(简单)", Enabled: true, Kind: "system", SystemRule: true, Sort: 9},
		{ID: "10005", Name: "滑块验证(简单)", Enabled: true, Kind: "system", SystemRule: true, Sort: 10},
	}
	custom := []RuleGroup{
		{ID: "10003", Name: "不得覆盖系统项", Enabled: false},
		{ID: "11111111-1111-4111-8111-111111111111", Name: "租户自定义", Enabled: true},
	}

	got := mergeRuleGroups(system, custom)
	want := append(append([]RuleGroup(nil), system...), RuleGroup{ID: "11111111-1111-4111-8111-111111111111", Name: "租户自定义", Enabled: true})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups = %#v, want %#v", got, want)
	}
}

func TestMergeRuleGroupsReturnsFreshSystemSlice(t *testing.T) {
	first := mergeRuleGroups([]RuleGroup{{ID: "1", Name: "系统", Enabled: true, Kind: "system", SystemRule: true}}, nil)
	first[0].Name = "changed"
	second := mergeRuleGroups([]RuleGroup{{ID: "1", Name: "系统", Enabled: true, Kind: "system", SystemRule: true}}, nil)
	if second[0].Name != "系统" {
		t.Fatalf("system rule groups leaked mutation: %#v", second[0])
	}
}

func TestSystemRuleLogicalKeyPrefersKeyAndFallsBackToRuleID(t *testing.T) {
	if got := systemRuleLogicalKey(" cc.challenge.5s ", "10005"); got != "cc.challenge.5s" {
		t.Fatalf("system rule key = %q", got)
	}
	if got := systemRuleLogicalKey(" ", "10005"); got != "10005" {
		t.Fatalf("legacy system rule id = %q", got)
	}
}
