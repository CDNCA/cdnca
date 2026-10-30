package rulepack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func readPack(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile("testdata/packs/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func compileFile(t *testing.T, name string) *CompiledPack {
	t.Helper()
	compiled, err := Compile(readPack(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return compiled
}

// mutate decodes a fixture, applies change to the generic document and
// compiles the result.
func mutate(t *testing.T, name string, change func(map[string]any)) error {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(readPack(t, name), &document); err != nil {
		t.Fatal(err)
	}
	change(document)
	encoded, _ := json.Marshal(document)
	_, err := Compile(encoded)
	return err
}

func firstRule(document map[string]any) map[string]any {
	return document["rules"].([]any)[0].(map[string]any)
}

func TestCompileFixturesCanonicalAndStable(t *testing.T) {
	for _, name := range []string{"system-sqli.json", "system-cc.json", "system-crs.json"} {
		compiled := compileFile(t, name)
		again, err := Load(compiled.Canonical, compiled.SHA256)
		if err != nil {
			t.Fatalf("%s: canonical bytes do not reload: %v", name, err)
		}
		if again.SHA256 != compiled.SHA256 {
			t.Fatalf("%s: digest drift", name)
		}
		// Load refuses a non-canonical spelling of the same pack.
		if _, err := Load(readPack(t, name), compiled.SHA256); err == nil {
			t.Fatalf("%s: non-canonical artifact accepted", name)
		}
	}
	sqli := compileFile(t, "system-sqli.json")
	if sqli.Pack.Rules[0].ID != "r010" || strings.Join(sqli.Pack.Exports, ",") != "r010,r020" {
		t.Fatalf("rules/exports not sorted: %+v %v", sqli.Pack.Rules[0].ID, sqli.Pack.Exports)
	}
	if string(sqli.Pack.Defaults[ParamExclusions]) != "[]" {
		t.Fatalf("defaults exclusions = %s", sqli.Pack.Defaults[ParamExclusions])
	}
	if crs := compileFile(t, "system-crs.json"); strings.Join(crs.Requires, ",") != RequiresWAFCRSModule {
		t.Fatalf("crs requires = %v", crs.Requires)
	}
}

func TestCompileSameDigestForEquivalentSpellings(t *testing.T) {
	compiled := compileFile(t, "system-sqli.json")
	var document map[string]any
	_ = json.Unmarshal(readPack(t, "system-sqli.json"), &document)
	// Reordered keys, rules and exports, different whitespace.
	rules := document["rules"].([]any)
	document["rules"] = []any{rules[1], rules[0]}
	document["exports"] = []any{"r010", "r020"}
	encoded, _ := json.MarshalIndent(document, "", "    ")
	other, err := Compile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if other.SHA256 != compiled.SHA256 {
		t.Fatal("equivalent spellings compile to different digests")
	}
}

func TestCompileRejectsInvalidPacks(t *testing.T) {
	cases := map[string]func(map[string]any){
		"schema":          func(d map[string]any) { d["schema"] = "cdnca.rule-pack/v2" },
		"namespace layer": func(d map[string]any) { d["pack_id"] = "dev/acme/sqli" },
		"user scope":      func(d map[string]any) { d["pack_id"], d["layer"] = "user/not-a-uuid/x", "user" },
		"semver":          func(d map[string]any) { d["version"] = "1.0" },
		"engine":          func(d map[string]any) { d["engine"] = "lua" },
		"unknown field":   func(d map[string]any) { d["script"] = "os.execute()" },
		"host is per site": func(d map[string]any) {
			firstRule(d)["waf"].(map[string]any)["match"].(map[string]any)["host"] = "a.example"
		},
		"duplicate rule":  func(d map[string]any) { d["rules"].([]any)[1].(map[string]any)["id"] = "r020" },
		"export not rule": func(d map[string]any) { d["exports"] = []any{"missing"} },
		"unbound param": func(d map[string]any) {
			d["params_schema"].(map[string]any)["x"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 2,
				"bind": map[string]any{"target": "cc.limit.requests", "rules": []any{}}}
		},
		"default missing": func(d map[string]any) { d["defaults"] = map[string]any{} },
		"default range":   func(d map[string]any) { d["defaults"] = map[string]any{"action": "allow"} },
		"wrong body":      func(d map[string]any) { firstRule(d)["cc"] = map[string]any{} },
		"min version":     func(d map[string]any) { d["engine_min_version"] = 2 },
		"bad action": func(d map[string]any) {
			firstRule(d)["waf"].(map[string]any)["action"] = "drop"
		},
	}
	for name, change := range cases {
		if err := mutate(t, "system-sqli.json", change); !errors.Is(err, ErrInvalidPack) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// ACL packs match only network conditions.
	err := mutate(t, "system-sqli.json", func(d map[string]any) { d["engine"] = "acl" })
	if !errors.Is(err, ErrInvalidPack) {
		t.Errorf("acl with path/inspect: %v", err)
	}
	// A CC rule needing CC API v4 (count_by) declared as v2.
	err = mutate(t, "system-cc.json", func(d map[string]any) {
		firstRule(d)["cc"].(map[string]any)["count_by"] = []any{map[string]any{"key": "host"}}
	})
	if !errors.Is(err, ErrInvalidPack) || !strings.Contains(err.Error(), "engine_min_version") {
		t.Errorf("cc count_by at v2: %v", err)
	}
	// A parameter range whose end the node model refuses (window 1..3600).
	err = mutate(t, "system-cc.json", func(d map[string]any) {
		d["params_schema"].(map[string]any)["requests"].(map[string]any)["maximum"] = 2000000
	})
	if !errors.Is(err, ErrInvalidPack) {
		t.Errorf("param boundary outside node limits: %v", err)
	}
	// CRS exports must be CRS rule IDs.
	err = mutate(t, "system-crs.json", func(d map[string]any) { d["exports"] = []any{"sqli"} })
	if !errors.Is(err, ErrInvalidPack) {
		t.Errorf("crs export: %v", err)
	}
}

func TestBudgetRejectsBacktrackingRegexAndRuleCount(t *testing.T) {
	regexRule := func(pattern string) func(map[string]any) {
		return func(d map[string]any) {
			firstRule(d)["waf"].(map[string]any)["match"] = map[string]any{"inspect": []any{map[string]any{
				"target": "args", "operator": "regex", "values": []any{pattern}}}}
		}
	}
	for _, pattern := range []string{`(a+)+$`, `(.*a){3}`, `(\w+\s?)*$`, `a{1000}`, `(?=x)a`, `(a)\1`, `.*a.*b.*c.*d.*e`} {
		if err := mutate(t, "system-sqli.json", regexRule(pattern)); !errors.Is(err, ErrInvalidPack) {
			t.Errorf("regex %q accepted: %v", pattern, err)
		}
	}
	for _, pattern := range []string{`(?i)union\s+select`, `^/api/v[0-9]+/`, `(a|b)*c`} {
		if err := mutate(t, "system-sqli.json", regexRule(pattern)); err != nil {
			t.Errorf("regex %q rejected: %v", pattern, err)
		}
	}
	err := mutate(t, "system-cc.json", func(d map[string]any) {
		rules := []any{}
		for index := 0; index < 129; index++ {
			rule := map[string]any{}
			encoded, _ := json.Marshal(firstRule(d))
			_ = json.Unmarshal(encoded, &rule)
			rule["id"] = fmt.Sprintf("r%03d", index)
			rules = append(rules, rule)
		}
		d["rules"], d["exports"] = rules, []any{}
		d["params_schema"], d["defaults"] = map[string]any{}, map[string]any{}
	})
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("129 CC rules: %v", err)
	}
	// Per-request cost: 64 body regexes x 4 clauses blow the unit budget.
	err = mutate(t, "system-sqli.json", func(d map[string]any) {
		values := []any{}
		for index := 0; index < 64; index++ {
			values = append(values, "x"+strconv.Itoa(index))
		}
		clause := map[string]any{"target": "body", "operator": "detect", "values": []any{"sqli", "xss"}}
		clauses := []any{}
		for index := 0; index < 4; index++ {
			clauses = append(clauses, clause)
		}
		rules := []any{}
		for index := 0; index < 200; index++ {
			rules = append(rules, map[string]any{"id": "b" + strconv.Itoa(index), "name": "x", "waf": map[string]any{
				"match": map[string]any{"inspect": clauses}, "action": "log", "flow": "continue"}})
		}
		d["rules"], d["exports"], d["params_schema"], d["defaults"] = rules, []any{}, map[string]any{}, map[string]any{}
	})
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("unit budget: %v", err)
	}
}

func TestMergeParamsAndInstantiate(t *testing.T) {
	sqli := compileFile(t, "system-sqli.json")
	params, err := MergeParams(sqli.Pack, Params{"action": json.RawMessage(`"log"`)}, map[string]bool{"r020": false})
	if err != nil {
		t.Fatal(err)
	}
	if string(params["action"]) != `"log"` || string(params[ParamExclusions]) != `["r020"]` {
		t.Fatalf("params = %s %s", params["action"], params[ParamExclusions])
	}
	rules, err := instantiate(sqli.Pack, params)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "r010" || rules[0].WAF.Action != "log" || rules[0].WAF.Control != "continue" {
		t.Fatalf("instantiated = %+v", rules)
	}
	if _, err := MergeParams(sqli.Pack, Params{"action": json.RawMessage(`"allow"`)}, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("out of enum: %v", err)
	}
	if _, err := MergeParams(sqli.Pack, nil, map[string]bool{"nope": false}); !errors.Is(err, ErrUnknownExport) {
		t.Fatalf("unknown export: %v", err)
	}
	crs := compileFile(t, "system-crs.json")
	params, _ = MergeParams(crs.Pack, nil, map[string]bool{"942110": false})
	rules, err = instantiate(crs.Pack, params)
	if err != nil || len(rules) != 1 || len(rules[0].CRS.ExcludeIDs) != 1 || rules[0].CRS.ExcludeIDs[0] != 942110 {
		t.Fatalf("crs exclusion: %+v %v", rules, err)
	}
}
