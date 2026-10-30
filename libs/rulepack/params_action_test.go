package rulepack

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// A log-only system pack lets the user switch the action to block /
// challenge (waf.action) or reject / challenge (cc.action.kind).
func TestActionParamsSwitchLogPacks(t *testing.T) {
	waf := []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"system/t-waf","version":"1.0.0","layer":"system",
	"engine":"waf_v2","engine_min_version":1,"name":"t","description":"",
	"params_schema":{"action":{"type":"string","enum":["log","block","challenge"],"bind":{"target":"waf.action","rules":[]}}},
	"exports":["r"],"rules":[{"id":"r","name":"r","waf":{"match":{"inspect":[{"target":"user_agent","operator":"contains","values":["sqlmap"]}]},"action":"log","flow":"continue"}}],
	"defaults":{"action":"log"}}`)
	compiled, err := Compile(waf)
	if err != nil {
		t.Fatal(err)
	}
	for action, flow := range map[string]edgeconfig.WAFControl{"log": edgeconfig.WAFContinue, "block": edgeconfig.WAFStop,
		"challenge": edgeconfig.WAFStop} {
		params, err := MergeParams(compiled.Pack, Params{"action": json.RawMessage(`"` + action + `"`)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := instantiate(compiled.Pack, params)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		rule := rules[0].WAF
		if string(rule.Action) != action || rule.Control != flow || (action == "challenge") != (rule.ActionConfig != nil) {
			t.Fatalf("%s: %+v", action, rule)
		}
	}

	cc := []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"system/t-cc","version":"1.0.0","layer":"system",
	"engine":"cc_v2","engine_min_version":3,"name":"t","description":"",
	"params_schema":{"action":{"type":"string","enum":["log","reject_429","challenge"],"bind":{"target":"cc.action.kind","rules":[]}}},
	"exports":["r"],"rules":[{"id":"r","name":"r","cc":{"rule_id":"","priority":0,"flow":"continue","dimension":"client_ip",
	"match":{"status_404_count":10},"limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"log"}}}],
	"defaults":{"action":"log"}}`)
	compiled, err = Compile(cc)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"log", "reject_429", "challenge"} {
		params, err := MergeParams(compiled.Pack, Params{"action": json.RawMessage(`"` + action + `"`)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := instantiate(compiled.Pack, params)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		rule := rules[0].CC
		if string(rule.Action.Kind) != action || (action == "log") != (rule.Flow == edgeconfig.CCV2FlowContinue) ||
			(action == "challenge") != (rule.Action.Challenge != nil) {
			t.Fatalf("%s: %+v", action, rule)
		}
	}
	// temporary_ban needs ban_seconds the enum cannot carry: not offered.
	var document map[string]any
	_ = json.Unmarshal(cc, &document)
	document["params_schema"].(map[string]any)["action"].(map[string]any)["enum"] = []string{"log", "temporary_ban"}
	encoded, _ := json.Marshal(document)
	if _, err := Compile(encoded); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("temporary_ban enum: %v", err)
	}
}
