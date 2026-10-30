package rulepack

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// A pack whose rules use a multipart_* inspect
// target needs CAPABILITY_NAME_WAF v5 on its nodes: packRequirements names
// RequiresWAFMultipart, so the publication gate refuses older nodes.
func TestPackRequiresWAFMultipart(t *testing.T) {
	plain := wafVPatchPack(`{"target":"user_agent","operator":"contains","values":["x"]}`, `{}`, `{}`)
	compiled, err := Compile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Requires) != 0 {
		t.Fatalf("plain pack requires %v", compiled.Requires)
	}
	multipart := wafVPatchPack(`{"target":"multipart_part_count","operator":"gt","values":["1000"]}`, `{}`, `{}`)
	if compiled, err = Compile(multipart); err != nil {
		t.Fatal(err)
	}
	if len(compiled.Requires) != 1 || compiled.Requires[0] != RequiresWAFMultipart {
		t.Fatalf("multipart pack requires %v", compiled.Requires)
	}
	resolution := Resolve([]MountRequest{{Pack: compiled, Priority: DefaultPriority}}, Target{})
	if resolution.Security == nil || len(resolution.Requires) != 1 || resolution.Requires[0] != RequiresWAFMultipart {
		t.Fatalf("resolution requires %v conflicts %v", resolution.Requires, resolution.Conflicts)
	}
}

// waf.inspect.number sets the single value of the bound rules' first
// number inspect clause: a site can raise the part count threshold.
func TestInspectNumberParam(t *testing.T) {
	pack := wafVPatchPack(`{"target":"multipart_part_count","operator":"gt","values":["1000"]}`,
		`{"max_parts":{"type":"integer","minimum":10,"maximum":100000,"bind":{"target":"waf.inspect.number","rules":["r"]}}}`,
		`{"max_parts":1000}`)
	compiled, err := Compile(pack)
	if err != nil {
		t.Fatal(err)
	}
	params, err := MergeParams(compiled.Pack, Params{"max_parts": json.RawMessage(`5000`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := instantiate(compiled.Pack, params)
	if err != nil {
		t.Fatal(err)
	}
	if got := rules[0].WAF.Match.Inspect[0].Values; len(got) != 1 || got[0] != "5000" {
		t.Fatalf("threshold %v", got)
	}
	if _, err := MergeParams(compiled.Pack, Params{"max_parts": json.RawMessage(`5`)}, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("below minimum accepted: %v", err)
	}
	// A rule without a number clause cannot bind it.
	bad := wafVPatchPack(`{"target":"user_agent","operator":"contains","values":["x"]}`,
		`{"n":{"type":"integer","minimum":1,"maximum":10,"bind":{"target":"waf.inspect.number","rules":[]}}}`, `{"n":1}`)
	if _, err := Compile(bad); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("text-only rule bound to waf.inspect.number: %v", err)
	}
	// action and a threshold bind different targets: both apply.
	both := wafVPatchPack(`{"target":"multipart_field_max_length","operator":"gt","values":["1048576"]}`,
		`{"action":{"type":"string","enum":["block","log"],"bind":{"target":"waf.action","rules":[]}},`+
			`"max_len":{"type":"integer","minimum":1024,"maximum":67108864,"bind":{"target":"waf.inspect.number","rules":[]}}}`,
		`{"action":"block","max_len":1048576}`)
	if compiled, err = Compile(both); err != nil {
		t.Fatal(err)
	}
	params, _ = MergeParams(compiled.Pack, Params{"action": json.RawMessage(`"log"`), "max_len": json.RawMessage(`2097152`)}, nil)
	rules, err = instantiate(compiled.Pack, params)
	if err != nil || rules[0].WAF.Action != edgeconfig.WAFLog || rules[0].WAF.Match.Inspect[0].Values[0] != "2097152" {
		t.Fatalf("%+v %v", rules, err)
	}
}

func wafVPatchPack(inspect, schema, defaults string) []byte {
	return []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"system/t-vpatch","version":"1.0.0","layer":"system",
	"engine":"waf_v2","engine_min_version":1,"name":"t","description":"","params_schema":` + schema + `,
	"exports":["r"],"rules":[{"id":"r","name":"r","waf":{"match":{"inspect":[` + inspect + `]},"action":"block","flow":"stop"}}],
	"defaults":` + defaults + `}`)
}

// Two parameters may bind one target when both name disjoint rule lists
// (the PHP pack: action for the blocking rules, soap_action for the
// log-only SOAP signal); overlapping or "every rule" lists stay refused.
func TestDisjointBindTargets(t *testing.T) {
	pack := func(schema, defaults string) []byte {
		return []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"system/t-two","version":"1.0.0","layer":"system",
	"engine":"waf_v2","engine_min_version":1,"name":"t","description":"","params_schema":` + schema + `,
	"exports":["a","b"],"rules":[
	{"id":"a","name":"a","waf":{"match":{"inspect":[{"target":"user_agent","operator":"contains","values":["x"]}]},"action":"block","flow":"stop"}},
	{"id":"b","name":"b","waf":{"match":{"inspect":[{"target":"user_agent","operator":"contains","values":["y"]}]},"action":"log","flow":"continue"}}],
	"defaults":` + defaults + `}`)
	}
	enum := `"type":"string","enum":["block","log"]`
	compiled, err := Compile(pack(`{"action":{`+enum+`,"bind":{"target":"waf.action","rules":["a"]}},`+
		`"soap_action":{`+enum+`,"bind":{"target":"waf.action","rules":["b"]}}}`, `{"action":"block","soap_action":"log"}`))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := instantiate(compiled.Pack, compiled.Pack.Defaults)
	if err != nil || rules[0].WAF.Action != edgeconfig.WAFBlock || rules[1].WAF.Action != edgeconfig.WAFLog {
		t.Fatalf("%+v %v", rules, err)
	}
	for _, schema := range []string{
		`{"action":{` + enum + `,"bind":{"target":"waf.action","rules":["a","b"]}},"soap_action":{` + enum + `,"bind":{"target":"waf.action","rules":["b"]}}}`,
		`{"action":{` + enum + `,"bind":{"target":"waf.action","rules":[]}},"soap_action":{` + enum + `,"bind":{"target":"waf.action","rules":["b"]}}}`,
	} {
		if _, err := Compile(pack(schema, `{"action":"block","soap_action":"log"}`)); !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("overlapping binds accepted: %s %v", schema, err)
		}
	}
}
