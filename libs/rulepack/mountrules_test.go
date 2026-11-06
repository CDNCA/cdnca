package rulepack

import (
	"encoding/json"
	"errors"
	"testing"
)

// MountRules: the control plane reads a published mount's own rule values (its params
// applied) by node rule ID, e.g. the ban seconds of a pack CC rule a node banned with.
func TestMountRulesAppliesParams(t *testing.T) {
	cc := compileFile(t, "system-cc.json")
	resolution := Resolve([]MountRequest{request(cc, 500)}, Target{})
	if resolution.Security == nil {
		t.Fatalf("conflicts = %+v", resolution.Conflicts)
	}
	mount := resolution.Security.Mounts[0]
	params := Params{}
	for key, value := range mount.Params {
		params[key] = value
	}
	params["requests"] = json.RawMessage("300")
	mount.Params = params
	rules, err := MountRules(mount, cc)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	rule := rules[0]
	if rule.NodeID != NodeRuleID(cc.Pack.PackID, "rate") || rule.CC == nil || rule.CC.Action.BanSeconds != 600 ||
		rule.CC.Limit.Requests != 300 {
		t.Fatalf("rule = %+v", rule)
	}
	other := compileFile(t, "system-sqli.json")
	if _, err := MountRules(mount, other); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("mount of another pack: %v", err)
	}
	if _, err := MountRules(mount, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("no pack: %v", err)
	}
}
