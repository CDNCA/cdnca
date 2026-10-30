package rulepack

import (
	"encoding/json"
	"strings"
	"testing"
)

const tenantA = "11111111-1111-4111-8111-111111111111"
const tenantB = "22222222-2222-4222-8222-222222222222"

// wafPack is a one-rule waf_v2 pack: action on path prefix.
func wafPack(t *testing.T, packID, action, path string) *CompiledPack {
	t.Helper()
	layer, _ := packIDLayer(packID)
	flow := "stop"
	if action == "log" {
		flow = "continue"
	}
	document := map[string]any{
		"schema": Schema, "pack_id": packID, "version": "1.0.0", "layer": layer, "engine": "waf_v2",
		"engine_min_version": 1, "name": packID, "description": "", "params_schema": map[string]any{},
		"exports": []any{"r1"}, "defaults": map[string]any{},
		"rules": []any{map[string]any{"id": "r1", "name": "r1", "waf": map[string]any{
			"match": map[string]any{"path": map[string]any{"kind": "prefix", "value": path}}, "action": action, "flow": flow}}},
	}
	encoded, _ := json.Marshal(document)
	compiled, err := Compile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func request(pack *CompiledPack, priority int) MountRequest {
	return MountRequest{Pack: pack, Priority: priority,
		Source: Source{EnabledAt: LevelRef{Level: LevelPlatform}, DisableAt: []LevelRef{{Level: LevelPlatform}}}}
}

func codes(conflicts []Conflict) string {
	out := []string{}
	for _, conflict := range conflicts {
		out = append(out, conflict.Code)
	}
	return strings.Join(out, ",")
}

func TestResolveOrdersUserBeforeDeveloperBeforeSystem(t *testing.T) {
	system := wafPack(t, "system/block-admin", "block", "/admin")
	developer := wafPack(t, "dev/acme/log-admin", "log", "/admin")
	user := wafPack(t, "user/"+tenantA+"/allow-admin", "allow", "/admin")
	systemB := wafPack(t, "system/a-first", "block", "/b")
	resolution := Resolve([]MountRequest{request(system, 500), request(systemB, 500), request(developer, 10), request(user, 900)}, Target{})
	if len(resolution.Conflicts) != 0 || resolution.Security == nil {
		t.Fatalf("conflicts = %+v", resolution.Conflicts)
	}
	order := []string{}
	for _, mount := range resolution.Security.Mounts {
		order = append(order, mount.PackID)
	}
	want := "user/" + tenantA + "/allow-admin,dev/acme/log-admin,system/a-first,system/block-admin"
	if strings.Join(order, ",") != want {
		t.Fatalf("order = %v", order)
	}
	// The user allow stops first: the system block on the same path is
	// shadowed (warning, not a conflict: the layers order them explicitly).
	if codes(resolution.Warnings) != WarningShadowed+","+WarningShadowed || resolution.Rules[0].WAF.Action != "allow" {
		t.Fatalf("warnings = %+v first = %+v", resolution.Warnings, resolution.Rules[0])
	}
	// Request order does not change the result.
	again := Resolve([]MountRequest{request(user, 900), request(developer, 10), request(systemB, 500), request(system, 500)}, Target{})
	if again.Security.ResolvedSHA256 != resolution.Security.ResolvedSHA256 {
		t.Fatal("resolved_sha256 depends on request order")
	}
}

func TestResolveConflictsListBothSidesAndDisableRemedies(t *testing.T) {
	allow := wafPack(t, "system/allow-x", "allow", "/x")
	block := wafPack(t, "system/block-x", "block", "/x")
	allowRequest := request(allow, 500)
	allowRequest.Source = Source{EnabledAt: LevelRef{Level: LevelTenant, ObjectID: tenantA},
		DisableAt: []LevelRef{{Level: LevelPlatform}, {Level: LevelTenant, ObjectID: tenantA}}}
	resolution := Resolve([]MountRequest{allowRequest, request(block, 500)}, Target{})
	if codes(resolution.Conflicts) != ConflictOppositeAction || resolution.Security != nil {
		t.Fatalf("conflicts = %+v", resolution.Conflicts)
	}
	conflict := resolution.Conflicts[0]
	if len(conflict.Sides) != 2 || conflict.Sides[0].PackID != "system/allow-x" ||
		conflict.Sides[0].EnabledAt.Level != LevelTenant || conflict.Sides[1].PackID != "system/block-x" {
		t.Fatalf("sides = %+v", conflict.Sides)
	}
	for _, remedy := range conflict.Remedies {
		if !strings.HasPrefix(remedy.Action, "disable_") {
			t.Fatalf("remedy %+v is not a disable", remedy)
		}
	}
	if len(conflict.Remedies) != 6 {
		t.Fatalf("remedies = %+v", conflict.Remedies)
	}
	// An explicit priority orders them: no conflict, the later one is shadowed.
	resolution = Resolve([]MountRequest{request(allow, 100), request(block, 500)}, Target{})
	if len(resolution.Conflicts) != 0 || codes(resolution.Warnings) != WarningShadowed {
		t.Fatalf("with priority: %+v / %+v", resolution.Conflicts, resolution.Warnings)
	}
	// Disabling one side (it is no longer an effective mount) resolves it.
	resolution = Resolve([]MountRequest{request(block, 500)}, Target{})
	if len(resolution.Conflicts) != 0 || resolution.Security == nil {
		t.Fatalf("one side: %+v", resolution.Conflicts)
	}
}

func TestResolveOtherConflicts(t *testing.T) {
	sqli := compileFile(t, "system-sqli.json")
	cc := compileFile(t, "system-cc.json")
	crs := compileFile(t, "system-crs.json")
	if got := codes(Resolve([]MountRequest{request(sqli, 1), request(sqli, 2)}, Target{}).Conflicts); got != ConflictDuplicatePack {
		t.Fatalf("duplicate: %s", got)
	}
	unknown := request(sqli, 1)
	unknown.RuleStates = map[string]bool{"not-exported": false}
	if got := codes(Resolve([]MountRequest{unknown}, Target{}).Conflicts); got != ConflictUnknownExport {
		t.Fatalf("unknown export: %s", got)
	}
	badParams := request(sqli, 1)
	badParams.Params = Params{"action": json.RawMessage(`"allow"`)}
	if got := codes(Resolve([]MountRequest{badParams}, Target{}).Conflicts); got != ConflictParamsInvalid {
		t.Fatalf("params: %s", got)
	}
	if got := codes(Resolve([]MountRequest{request(cc, 1)}, Target{EngineVersions: map[Engine]uint32{EngineCCV2: 1}}).Conflicts); got != ConflictEngineVersion {
		t.Fatalf("engine version: %s", got)
	}
	if got := codes(Resolve([]MountRequest{request(cc, 1)}, Target{EngineVersions: map[Engine]uint32{EngineCCV2: 6}}).Conflicts); got != "" {
		t.Fatalf("engine version ok: %s", got)
	}
	other := mustCompileModified(t, "system-crs.json", func(d map[string]any) { d["pack_id"] = "system/crs-pl2" })
	if got := codes(Resolve([]MountRequest{request(crs, 1), request(other, 1)}, Target{}).Conflicts); got != ConflictEngineSingleton {
		t.Fatalf("singleton: %s", got)
	}
}

func mustCompileModified(t *testing.T, name string, change func(map[string]any)) *CompiledPack {
	t.Helper()
	var document map[string]any
	_ = json.Unmarshal(readPack(t, name), &document)
	change(document)
	encoded, _ := json.Marshal(document)
	compiled, err := Compile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestResolveCCPrioritiesAndNodeIDs(t *testing.T) {
	cc := compileFile(t, "system-cc.json")
	ccB := mustCompileModified(t, "system-cc.json", func(d map[string]any) { d["pack_id"] = "system/cc-b" })
	resolution := Resolve([]MountRequest{request(ccB, 500), request(cc, 500)}, Target{})
	if resolution.Security == nil || len(resolution.Rules) != 2 {
		t.Fatalf("resolution = %+v", resolution.Conflicts)
	}
	if resolution.Rules[0].CC.Priority != 1 || resolution.Rules[1].CC.Priority != 2 ||
		resolution.Rules[0].CC.RuleID != NodeRuleID("system/cc-b", "rate") || resolution.Rules[0].CC.Limit.Requests != 200 {
		t.Fatalf("rules = %+v %+v", resolution.Rules[0].CC, resolution.Rules[1].CC)
	}
	if NodeRuleID("system/cc-basic", "rate") == NodeRuleID("system/cc-b", "rate") {
		t.Fatal("node IDs collide across packs")
	}
}

func TestVerifyReproducesResolvedDigest(t *testing.T) {
	sqli := compileFile(t, "system-sqli.json")
	cc := compileFile(t, "system-cc.json")
	user := wafPack(t, "user/"+tenantA+"/allow-admin", "allow", "/admin")
	sqliRequest := request(sqli, 500)
	sqliRequest.Params = Params{"action": json.RawMessage(`"log"`)}
	sqliRequest.RuleStates = map[string]bool{"r020": false}
	resolution := Resolve([]MountRequest{sqliRequest, request(cc, 500), request(user, 500)}, Target{})
	if resolution.Security == nil {
		t.Fatalf("conflicts = %+v", resolution.Conflicts)
	}
	// Indented like a stored document: whitespace inside params must not
	// matter (the agent differential test reads an indented golden).
	wire, _ := json.MarshalIndent(resolution.Security, "", "  ")
	packs := map[string]*CompiledPack{}
	for _, pack := range []*CompiledPack{sqli, cc, user} {
		loaded, err := Load(pack.Canonical, pack.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		packs[loaded.SHA256] = loaded
	}
	var decoded Security
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	rules, err := Verify(decoded, packs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(resolution.Rules) {
		t.Fatalf("node rules %d, authority %d", len(rules), len(resolution.Rules))
	}
	tampered := decoded
	tampered.Mounts = append([]Mount{}, decoded.Mounts...)
	sqliIndex := -1
	for index, mount := range tampered.Mounts {
		if mount.PackID == "system/sqli-basic" {
			sqliIndex = index
		}
	}
	// Same params rebuilt from parts verify (sanity of the tamper below).
	tampered.Mounts[sqliIndex].Params = Params{"action": json.RawMessage(`"log"`), ParamExclusions: json.RawMessage(`["r020"]`)}
	if _, err := Verify(tampered, packs); err != nil {
		t.Fatalf("identical params rejected: %v", err)
	}
	tampered.Mounts[sqliIndex].Params = Params{"action": json.RawMessage(`"block"`), ParamExclusions: json.RawMessage(`["r020"]`)}
	if _, err := Verify(tampered, packs); err == nil {
		t.Fatal("tampered params verified")
	}
	// A non-canonical spelling of the same value (not just whitespace).
	tampered.Mounts[sqliIndex].Params = Params{"action": json.RawMessage(`"\u006cog"`), ParamExclusions: json.RawMessage(`["r020"]`)}
	if _, err := Verify(tampered, packs); err == nil {
		t.Fatal("non-canonical params verified")
	}
	swapped := decoded
	swapped.Mounts = []Mount{decoded.Mounts[2], decoded.Mounts[1], decoded.Mounts[0]}
	if _, err := Verify(swapped, packs); err == nil {
		t.Fatal("reordered mounts verified")
	}
	delete(packs, sqli.SHA256)
	if _, err := Verify(decoded, packs); err == nil {
		t.Fatal("missing pack verified")
	}
}

// Resolve refuses mounts whose compiled match index is over budget (ADR
// 0011 §6.5): 300 rules (site budget permitting) without any key.
func TestResolveCompiledCostBudget(t *testing.T) {
	savedSite, savedPack := siteBudget, packBudget
	siteBudget = Budget{Rules: 1 << 16, Regexes: 1 << 16, Units: 1 << 30}
	packBudget = siteBudget
	defer func() { siteBudget, packBudget = savedSite, savedPack }()
	var rules []any
	for n := 0; n < 300; n++ {
		id := "r" + itoa(n)
		rules = append(rules, map[string]any{"id": id, "name": id, "waf": map[string]any{
			"match":  map[string]any{"inspect": []any{map[string]any{"target": "args", "operator": "detect", "values": []any{"sqli"}}}},
			"action": "log", "flow": "continue"}})
	}
	encoded, _ := json.Marshal(map[string]any{
		"schema": Schema, "pack_id": "system/unkeyed", "version": "1.0.0", "layer": "system", "engine": "waf_v2",
		"engine_min_version": 1, "name": "unkeyed", "description": "", "params_schema": map[string]any{},
		"exports": []any{}, "defaults": map[string]any{}, "rules": rules})
	unkeyed, err := Compile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	resolution := Resolve([]MountRequest{request(unkeyed, 1)}, Target{})
	if codes(resolution.Conflicts) != ConflictBudget || resolution.Security != nil ||
		!strings.Contains(resolution.Conflicts[0].Message, "unkeyed rules over 256") {
		t.Fatalf("conflicts %+v", resolution.Conflicts)
	}
}
