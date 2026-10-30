package rulepack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// tuningDocument is a system/crs-tuning pack: entries (number, min paranoia,
// rule, "loc:name" targets), every entry exported.
func tuningDocument(entries ...[]any) map[string]any {
	rules, exports := []any{}, []any{}
	for _, entry := range entries {
		targets := []any{}
		for _, text := range entry[3].([]string) {
			location, name, _ := strings.Cut(text, ":")
			targets = append(targets, map[string]any{"loc": location, "name": name})
		}
		id := entry[0].(string)
		rules = append(rules, map[string]any{"id": id, "name": "排除 " + id,
			"tuning": map[string]any{"min_paranoia": entry[1], "rule": entry[2], "targets": targets}})
		exports = append(exports, id)
	}
	return map[string]any{"schema": Schema, "pack_id": CRSTuningPackID, "version": "1.0.0", "layer": "system",
		"engine": "modsecurity", "engine_min_version": 1, "name": "CRS 官方调优", "description": "",
		"params_schema": map[string]any{}, "exports": exports, "rules": rules, "defaults": map[string]any{}}
}

func compileDocument(document map[string]any) (*CompiledPack, error) {
	encoded, _ := json.Marshal(document)
	return Compile(encoded)
}

func tuningPack(t *testing.T) *CompiledPack {
	t.Helper()
	compiled, err := compileDocument(tuningDocument(
		[]any{"1", 1, 942100, []string{"args:q", "cookie:sid"}},
		[]any{"7", 2, 941100, []string{"args:json.body"}}))
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestCRSTuningPackFormat(t *testing.T) {
	compiled := tuningPack(t)
	if compiled.Cost.Rules != 0 || len(compiled.Pack.Exports) != 2 {
		t.Fatalf("cost %+v exports %v", compiled.Cost, compiled.Pack.Exports)
	}
	entries, err := TuningEntries(compiled)
	if err != nil || len(entries) != 2 || entries[0].ID != 1 || entries[1].ID != 7 || entries[1].Rule != 941100 ||
		entries[0].Targets[1] != (edgeconfig.CRSTuningTarget{Location: "cookie", Name: "sid"}) {
		t.Fatalf("entries %+v %v", entries, err)
	}
	for name, change := range map[string]func(map[string]any){
		"leading zero":   func(d map[string]any) { setRule(d, 0, "id", "01") },
		"entry 0":        func(d map[string]any) { setRule(d, 0, "id", "0") },
		"not a number":   func(d map[string]any) { setRule(d, 0, "id", "a1") },
		"wildcard":       func(d map[string]any) { setTarget(d, "*") },
		"regex":          func(d map[string]any) { setTarget(d, "/q/") },
		"ARGS prefix":    func(d map[string]any) { setTarget(d, "ARGS:q") },
		"not exported":   func(d map[string]any) { d["exports"] = []any{} },
		"params":         func(d map[string]any) { d["params_schema"] = map[string]any{"x": map[string]any{"type": "boolean"}} },
		"crs body":       func(d map[string]any) { tuningRule(d)["crs"] = map[string]any{"files": []any{"REQUEST-942"}} },
		"no tuning body": func(d map[string]any) { delete(tuningRule(d), "tuning") },
		"paranoia 0":     func(d map[string]any) { tuningRule(d)["tuning"].(map[string]any)["min_paranoia"] = 0 },
		"not CRS rule":   func(d map[string]any) { tuningRule(d)["tuning"].(map[string]any)["rule"] = 100 },
		"developer":      func(d map[string]any) { d["pack_id"], d["layer"] = "dev/io.cdnca.x/crs-tuning", "developer" },
	} {
		document := tuningDocument([]any{"1", 1, 942100, []string{"args:q"}})
		change(document)
		if _, err := compileDocument(document); !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// a tuning body is only for system/crs-tuning
	other := tuningDocument([]any{"1", 1, 942100, []string{"args:q"}})
	other["pack_id"] = "system/crs-other"
	if _, err := compileDocument(other); err == nil {
		t.Fatal("tuning body outside system/crs-tuning accepted")
	}
	// more entries than a normal pack's rule budget
	many := make([][]any, 0, 300)
	for index := 1; index <= 300; index++ {
		many = append(many, []any{itoa(index), 1, 942100, []string{"args:p" + itoa(index)}})
	}
	if _, err := compileDocument(tuningDocument(many...)); err != nil {
		t.Fatalf("300 entries: %v", err)
	}
}

func tuningRule(document map[string]any) map[string]any {
	return document["rules"].([]any)[0].(map[string]any)
}

func setRule(document map[string]any, index int, key string, value any) {
	document["rules"].([]any)[index].(map[string]any)[key] = value
	if key == "id" {
		document["exports"] = []any{value}
	}
}

func setTarget(document map[string]any, name string) {
	tuningRule(document)["tuning"].(map[string]any)["targets"] = []any{map[string]any{"loc": "args", "name": name}}
}

func sha256Of(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Resolve: one CRS selection pack and one tuning pack coexist (ADR 0011
// §6.4); two of either kind conflict; the tuning pack's disabled entries are
// its exclusions and change resolved_sha256.
func TestResolveCRSTuningCoexists(t *testing.T) {
	crs, tuning := compileFile(t, "system-crs.json"), tuningPack(t)
	resolution := Resolve([]MountRequest{request(crs, 1), request(tuning, 1)}, Target{})
	if resolution.Security == nil || len(resolution.Security.Mounts) != 2 {
		t.Fatalf("CRS + tuning: %s", codes(resolution.Conflicts))
	}
	for _, rule := range resolution.Rules {
		if rule.PackID == CRSTuningPackID {
			t.Fatal("tuning entries became node rules")
		}
	}
	other := mustCompileModified(t, "system-crs.json", func(d map[string]any) { d["pack_id"] = "system/crs-pl2" })
	if got := codes(Resolve([]MountRequest{request(crs, 1), request(other, 1), request(tuning, 1)}, Target{}).Conflicts); got != ConflictEngineSingleton {
		t.Fatalf("two CRS packs with tuning: %s", got)
	}
	// a second tuning pack cannot exist under another ID; the same ID twice
	// is a duplicate
	if got := codes(Resolve([]MountRequest{request(tuning, 1), request(tuning, 2)}, Target{}).Conflicts); got != ConflictDuplicatePack {
		t.Fatalf("tuning twice: %s", got)
	}
	// tuning alone resolves (a site without managed WAF: the node renders
	// nothing for it)
	if alone := Resolve([]MountRequest{request(tuning, 1)}, Target{}); alone.Security == nil {
		t.Fatalf("tuning alone: %s", codes(alone.Conflicts))
	}
	disabled := request(tuning, 1)
	disabled.RuleStates = map[string]bool{"7": false}
	off := Resolve([]MountRequest{request(crs, 1), disabled}, Target{})
	if off.Security == nil || off.Security.ResolvedSHA256 == resolution.Security.ResolvedSHA256 {
		t.Fatal("disabling an entry does not change resolved_sha256")
	}
	unknown := request(tuning, 1)
	unknown.RuleStates = map[string]bool{"8": false}
	if got := codes(Resolve([]MountRequest{unknown}, Target{}).Conflicts); got != ConflictUnknownExport {
		t.Fatalf("unknown entry: %s", got)
	}
	// TuningOf: entries and the site's u= list
	packs := map[string]*CompiledPack{crs.SHA256: crs, tuning.SHA256: tuning}
	entries, list, mounted, err := TuningOf(off.Security.Mounts, packs)
	if err != nil || !mounted || len(entries) != 2 || len(list) != 1 || list[0] != 7 {
		t.Fatalf("TuningOf %+v %v %v %v", entries, list, mounted, err)
	}
	if _, _, mounted, err := TuningOf(Resolve([]MountRequest{request(crs, 1)}, Target{}).Security.Mounts, packs); mounted || err != nil {
		t.Fatalf("no tuning mount: %v %v", mounted, err)
	}
	// Verify (node precheck) reproduces the digest with the tuning mount
	if _, err := Verify(*off.Security, packs); err != nil {
		t.Fatal(err)
	}
}

// The tuning pack never takes the CRS profile's place: SiteCRSExclusions
// and CheckCRSProfile ignore it (it selects no CRS rule).
func TestCRSTuningIsNotACRSSelection(t *testing.T) {
	manifest, profile := narrowFixture(t)
	tuning := tuningPack(t)
	resolution := Resolve([]MountRequest{request(tuning, 1)}, Target{})
	packs := map[string]*CompiledPack{tuning.SHA256: tuning}
	exclusions, ok, err := SiteCRSExclusions(resolution.Security.Mounts, packs, manifest, &profile, []int{942100})
	if err != nil || ok || len(exclusions) != 1 {
		t.Fatalf("SiteCRSExclusions %v %v %v", exclusions, ok, err)
	}
	// no managed WAF: still not out of profile
	if _, _, err := SiteCRSExclusions(resolution.Security.Mounts, packs, manifest, nil, nil); err != nil {
		t.Fatal(err)
	}
	checked := CheckCRSProfile(resolution, []MountRequest{request(tuning, 1)}, manifest, nil, nil)
	if checked.Security == nil {
		t.Fatalf("CheckCRSProfile: %s", codes(checked.Conflicts))
	}
	// the quality gate checks the entries name rules of the CRS text
	if ids, err := CheckPublishable(tuning, manifest); err != nil || ids != nil {
		t.Fatalf("gate: %v %v", ids, err)
	}
	bad, err := compileDocument(tuningDocument([]any{"1", 1, 999999, []string{"args:q"}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPublishable(bad, manifest); err == nil {
		t.Fatal("entry on a rule the CRS text lacks passes the gate")
	}
	if _, err := CheckPublishable(tuning, nil); err == nil {
		t.Fatal("gate without CRS text")
	}
	// sealing computes no CRS rule list for it
	sealed, err := Seal(tuning.Canonical, make([]byte, CEKSize), manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Of(sealed)
	opened, err := OpenManifest(sealed, digest)
	if err != nil || len(opened.CRSRuleIDs) != 0 {
		t.Fatalf("sealed tuning: %v %v", opened, err)
	}
	if _, _, _, err := TuningOf([]Mount{{PackID: CRSTuningPackID, SHA256: opened.SHA256, Engine: EngineModSecurity}},
		map[string]*CompiledPack{opened.SHA256: opened}); err == nil {
		t.Fatal("sealed tuning pack rendered from its manifest")
	}
	unsealed, err := Open(sealed, digest, make([]byte, CEKSize))
	if err != nil {
		t.Fatal(err)
	}
	if entries, _, _, err := TuningOf([]Mount{{PackID: CRSTuningPackID, SHA256: digest, Engine: EngineModSecurity,
		Params: Params{ParamExclusions: json.RawMessage(`[]`)}}}, map[string]*CompiledPack{digest: unsealed}); err != nil || len(entries) != 2 {
		t.Fatalf("opened sealed tuning: %v %v", entries, err)
	}
}

// Intelligence mark packs only mark: log + continue, nothing terminal
// (ADR 0011 §6.4: no opposite-action conflict with user rules).
func TestIntelMarkPacksOnlyMark(t *testing.T) {
	mark := func(packID, action, flow string) map[string]any {
		return map[string]any{"schema": Schema, "pack_id": packID, "version": "1.0.0", "layer": "system", "engine": "waf_v2",
			"engine_min_version": 1, "name": "情报", "description": "", "params_schema": map[string]any{}, "exports": []any{},
			"defaults": map[string]any{}, "rules": []any{map[string]any{"id": "s1", "name": "扫描器 UA",
				"waf": map[string]any{"match": map[string]any{"path": map[string]any{"kind": "prefix", "value": "/.env"}},
					"action": action, "flow": flow}}}}
	}
	for _, id := range []string{AutoDefenseIntelPackID, ScannerSignaturesPackID} {
		compiled, err := compileDocument(mark(id, "log", "continue"))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		for action, flow := range map[string]string{"block": "stop", "allow": "stop", "log": "stop"} {
			if _, err := compileDocument(mark(id, action, flow)); err == nil {
				t.Fatalf("%s %s/%s accepted", id, action, flow)
			}
		}
		user := compileFile(t, "user-allow.json")
		resolution := Resolve([]MountRequest{request(user, 1), request(compiled, 1)}, Target{})
		if resolution.Security == nil {
			t.Fatalf("%s with a user allow: %s", id, codes(resolution.Conflicts))
		}
		plan, err := MountRulePlan(resolution.Rules, func(string) string { return strings.Repeat("a", 64) }, false)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, segment := range plan.Segments {
			found = found || segment.PolicyID == IntelPackLabel(id)
		}
		if !found {
			t.Fatalf("%s: no segment labelled %s", id, IntelPackLabel(id))
		}
	}
	// other packs may still block
	if _, err := compileDocument(mark("system/other-sig", "block", "stop")); err != nil {
		t.Fatal(err)
	}
}

// system/crs-tuning 的 ID 也匹配档位包命名（crs-*），但它不是档位包：CRSProfileOf 必须拒绝而不是解引用空的 CRS 体。
func TestCRSTuningPackIsNotACRSProfile(t *testing.T) {
	if _, err := CRSProfileOf(tuningPack(t)); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("tuning pack accepted as a CRS profile: %v", err)
	}
	if IsCRSProfilePack(CRSTuningPackID) {
		t.Fatal("system/crs-tuning named a CRS profile pack")
	}
}
