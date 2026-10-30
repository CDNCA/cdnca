package rulepack

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// crsProfileLevel is one system/crs-<level> profile (the WAF protection
// tiers): the listed CRS rule sets of the catalog
// at paranoia max(level, the set's catalog paranoia), anomaly threshold 5,
// one action. Tiers are strictly increasing: each tier's sets contain the
// previous tier's and its paranoia never drops (TestCRSProfileTiersIncrease);
// 仅记录 has 标准防护's scope and only records.
type crsProfileLevel struct {
	name, display, description string
	paranoia                   int
	action                     string
	sets                       []string
	// weakThreshold > 0: two-level scoring (no preset exclusions, a better
	// decision): PL1 rules stay
	// strong at threshold 5 (标准防护's decision, so the tier contains it);
	// higher paranoia heuristics only count together with other signals.
	// Initial value, to be calibrated on cdnca-waf-check -only eval.
	weakThreshold int
}

var (
	crsStandardSets = []string{"crs_sqli", "crs_xss", "crs_file_upload", "crs_file_include", "crs_cmd_injection"}
	crsStrictSets   = append(append([]string{}, crsStandardSets...),
		"crs_java_code_injection", "crs_java_deserialization", "crs_php_code_injection", "crs_php_deserialization", "crs_ssti", "crs_generic")
)

var crsProfileLevels = []crsProfileLevel{
	{"pl1-log", "仅记录", "与「标准防护」判定范围相同（SQL注入、XSS、文件上传、文件包含、命令注入，防护等级 1），命中只记录不拦截，用于上线前观察误报", 1, "log", crsStandardSets, 0},
	{"pl1", "标准防护", "拦截 SQL注入、XSS、文件上传、文件包含、命令注入 5 类攻击（OWASP CRS 防护等级 1，误报最少，推荐默认）；异常分达到 5 即拦截", 1, "block", crsStandardSets, 0},
	{"pl2", "严格防护", "在标准防护基础上增加 Java代码注入、Java反序列化、PHP代码注入、PHP反序列化、SSTI模板注入、通用代码注入与SSRF 6 类，共 11 类攻击，并启用 OWASP CRS 防护等级 2 规则；等级 2 启发式规则需多个信号同时命中（累计分达到 10）才拦截，单条命中只计分", 2, "block", crsStrictSets, 10},
	{"pl3", "极严格防护", "11 类攻击全部启用 OWASP CRS 防护等级 3 规则，面向高风险站点；等级 2–3 启发式规则多信号累计分达到 10 即拦截，判定范围包含严格防护", 3, "block", crsStrictSets, 10},
}

// crsProfileVersion is the tier packs' version (1.0.0 = migration 087's ten
// sets per level; 1.1.0 = the four tiers, license migration 090; 1.2.0 =
// two-level scoring of the strict tiers, waf-strict-algo, and the adaptive
// WAF fields grey_action/adaptive of ADR 0011 RI-02 in the same unreleased
// version, license migration 098; 1.3.0 = waf-gap5: REQUEST-934 as the
// eleventh class crs_generic in 严格防护 and above, license migration 9xx).
// 1.4.0 = waf-gap7: learned weak weights (crsLearnedWeakWeights), license
// migration 9xx.
const crsProfileVersion = "1.4.0"

// crsLearnedWeakWeights (waf-gap7 S1) are the weak rules' scores learned
// offline by scripts/security/datasets/learn_weights.py --keep-tpr (vectors
// runs/gap6-vec: gotestwaf, wafcomp-mal/legit, leipzig; evaluations
// runs/gap5-after: seed 5 batches + CRS regression; 70/30 split by request
// ID): only lowered from the severity, an evaluated attack the tier blocked
// stays blocked, the training set's blocked attacks do not drop. The two
// strict tiers share them (one weight list per set key on a node).
var crsLearnedWeakWeights = map[int]int{
	931130: 4, 932220: 4, 932271: 0, 932331: 4, 941330: 4, 941340: 4,
	941380: 4, 942101: 1, 942200: 2, 942251: 1, 942260: 0, 942431: 2,
}

// crsWeakWeightsOf is a two-level set's learned weights: those of its
// members above the strong paranoia, ascending (nil: none).
func crsWeakWeightsOf(set rulecatalog.WAFEngineSet, manifest *edgeconfig.CRSManifest) []rulecatalog.WAFWeight {
	excluded := map[int]bool{}
	for _, rule := range set.ExcludeIDs {
		excluded[rule] = true
	}
	var weights []rulecatalog.WAFWeight
	for _, rule := range manifest.Rules {
		weight, learned := crsLearnedWeakWeights[rule.ID]
		member := slices.Contains(set.IncludeIDs, rule.ID)
		for _, file := range set.Files {
			member = member || strings.HasPrefix(rule.File, file+"-")
		}
		if learned && member && !excluded[rule.ID] && rule.Paranoia > set.StrongParanoia {
			weights = append(weights, rulecatalog.WAFWeight{Rule: rule.ID, Weight: weight})
		}
	}
	sort.Slice(weights, func(i, j int) bool { return weights[i].Rule < weights[j].Rule })
	return weights
}

// CRSProfileGoldenDir holds the generated system/crs-* packs in canonical
// form: the bytes license migration 087 seeds (the license integration test
// reads them from here).
const crsProfileGoldenDir = "testdata/crs-profiles"

func catalogCRSText(t *testing.T) *edgeconfig.CRSRuleText {
	t.Helper()
	bundle := rulecatalog.CRSRulesBundle()
	files, err := rulecatalog.DecodeWAFEngineBundle(*bundle)
	if err != nil {
		t.Fatal(err)
	}
	return &edgeconfig.CRSRuleText{Version: bundle.Version, Files: files}
}

// buildCRSProfilePack generates one level's pack from the catalog's CRS rule
// sets (rulecatalog.CRSWAFSeed) and the CRS rule text (exports: every
// scoring rule a set evaluates at its paranoia level).
func buildCRSProfilePack(t *testing.T, level crsProfileLevel, manifest *edgeconfig.CRSManifest) Pack {
	t.Helper()
	pack := Pack{Schema: Schema, PackID: "system/crs-" + level.name, Version: crsProfileVersion, Layer: LayerSystem,
		Engine: EngineModSecurity, EngineMinVersion: 1, Name: level.display, Description: level.description,
		LicenseSPDX: "Apache-2.0", ParamsSchema: map[string]ParamSpec{}, Defaults: Params{}}
	exports := map[int]bool{}
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CRSWAFSeed() {
		items[strings.TrimPrefix(item.SystemKey, "waf_set:")] = item
	}
	for _, key := range level.sets {
		item := items[key]
		body := item.Body.WAFRuleSet
		if body == nil || body.Engine == nil {
			t.Fatalf("%s: catalog has no CRS rule set %s", level.name, key)
		}
		set := copyCRS(*body.Engine)
		set.Action, set.Paranoia = level.action, max(level.paranoia, set.Paranoia)
		if level.weakThreshold > 0 && set.Paranoia > 1 {
			// adaptive WAF (ADR 0011 RI-02): the grey zone challenges browser
			// requests (only these tiers), the
			// weak rules may be excluded or tightened automatically; no
			// official reweighting yet (strong_rules empty)
			set.StrongParanoia, set.WeakThreshold = 1, level.weakThreshold
			set.GreyAction, set.Adaptive = rulecatalog.WAFGreyChallenge, true
			set.WeakWeights = crsWeakWeightsOf(set, manifest)
		}
		id := strings.TrimPrefix(item.SystemKey, "waf_set:")
		pack.Rules = append(pack.Rules, Rule{ID: id, Name: strings.TrimPrefix(item.Name, "CRS·"), CRS: &set})
		excluded := map[int]bool{}
		for _, rule := range set.ExcludeIDs {
			excluded[rule] = true
		}
		for _, rule := range manifest.Rules {
			member := false
			for _, file := range set.Files {
				member = member || strings.HasPrefix(rule.File, file+"-")
			}
			for _, included := range set.IncludeIDs {
				member = member || rule.ID == included
			}
			if member && !excluded[rule.ID] && rule.Paranoia <= set.Paranoia {
				exports[rule.ID] = true
			}
		}
	}
	ids := make([]int, 0, len(exports))
	for id := range exports {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		pack.Exports = append(pack.Exports, strconv.Itoa(id))
	}
	return pack
}

// TestSystemCRSProfilePacksMatchGenerator regenerates the system/crs-* packs
// from the catalog and requires the golden files to be exactly their
// canonical bytes (go test -run TestSystemCRSProfilePacks -update rewrites).
func TestSystemCRSProfilePacksMatchGenerator(t *testing.T) {
	text := catalogCRSText(t)
	manifest, err := edgeconfig.DeriveCRSManifest(text)
	if err != nil {
		t.Fatal(err)
	}
	if *updateGolden {
		if err := os.MkdirAll(crsProfileGoldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, level := range crsProfileLevels {
		compiled, err := CompilePack(buildCRSProfilePack(t, level, manifest))
		if err != nil {
			t.Fatalf("%s: %v", level.name, err)
		}
		path := filepath.Join(crsProfileGoldenDir, "crs-"+level.name+".json")
		if *updateGolden {
			if err := os.WriteFile(path, compiled.Canonical, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		golden, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(golden, compiled.Canonical) {
			t.Fatalf("%s is stale; rerun with -update", path)
		}
		// The stored bytes load as they are delivered and resolve against the
		// catalog's CRS rule text.
		loaded, profile, err := LoadCRSProfile(golden, compiled.SHA256)
		if err != nil || loaded.SHA256 != compiled.SHA256 {
			t.Fatalf("%s load: %v", level.name, err)
		}
		resolved, err := edgeconfig.ResolveCRSProfile(text, profile)
		if err != nil || len(resolved.Sets) != len(level.sets) || len(resolved.Exports) == 0 ||
			len(resolved.Exports) > edgeconfig.MaxManagedWAFExclusions {
			t.Fatalf("%s resolve: sets %d exports %d: %v", level.name, len(resolved.Sets), len(resolved.Exports), err)
		}
		for _, set := range resolved.Sets {
			twoLevel := set.StrongParanoia == 1 && set.WeakThreshold == level.weakThreshold && set.GreyAction == "challenge" && set.Adaptive
			if set.Action != level.action || set.Paranoia < level.paranoia || set.Threshold != 5 || (level.weakThreshold > 0) != twoLevel ||
				level.weakThreshold == 0 && (set.GreyAction != "" || set.Adaptive) || set.StrongRules != nil {
				t.Fatalf("%s set %+v", level.name, set)
			}
		}
		if loaded.Pack.LicenseSPDX != "Apache-2.0" {
			t.Fatalf("%s license %q", level.name, loaded.Pack.LicenseSPDX)
		}
	}
}

func TestCRSProfileOfRequiresAProfilePack(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(crsProfileGoldenDir, "crs-pl1.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(golden)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := CRSProfileOf(compiled)
	if err != nil || profile.Ref.PackID != "system/crs-pl1" || profile.Ref.SHA256 != compiled.SHA256 ||
		profile.Sets[0].Key != "waf_set:crs_cmd_injection" {
		t.Fatalf("profile = %+v, %v", profile.Ref, err)
	}
	if _, _, err := LoadCRSProfile(golden, strings.Repeat("0", 64)); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	mutated := func(change func(map[string]any)) *CompiledPack {
		var document map[string]any
		if err := json.Unmarshal(golden, &document); err != nil {
			t.Fatal(err)
		}
		change(document)
		encoded, _ := json.Marshal(document)
		compiled, err := Compile(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return compiled
	}
	for name, change := range map[string]func(map[string]any){
		"not a profile id": func(d map[string]any) { d["pack_id"] = "system/sqli" },
		"exclusions preset": func(d map[string]any) {
			d["defaults"] = map[string]any{"exclusions": []any{"942100"}}
		},
	} {
		if _, err := CRSProfileOf(mutated(change)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := CRSProfileOf(compileFile(t, "system-sqli.json")); err == nil {
		t.Fatal("a waf_v2 pack accepted as a CRS profile")
	}
}

// loadedCRSProfiles is the four golden tier packs as the control plane loads them.
func loadedCRSProfiles(t *testing.T) []edgeconfig.CRSProfile {
	t.Helper()
	profiles := []edgeconfig.CRSProfile{}
	for _, level := range crsProfileLevels {
		golden, err := os.ReadFile(filepath.Join(crsProfileGoldenDir, "crs-"+level.name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := Compile(golden)
		if err != nil {
			t.Fatal(err)
		}
		_, profile, err := LoadCRSProfile(golden, compiled.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func crsSetOrder() []string {
	order := []string{}
	for _, item := range rulecatalog.CRSWAFSeed() {
		order = append(order, item.SystemKey)
	}
	return order
}

// TestCRSProfileTiersIncrease: the four tiers are strictly increasing: each contains every class of the previous one, no
// class's paranoia drops, every scoring rule of the previous tier is still
// evaluated, and each tier adds something (counted from the CRS rule text).
func TestCRSProfileTiersIncrease(t *testing.T) {
	manifest, err := edgeconfig.DeriveCRSManifest(catalogCRSText(t))
	if err != nil {
		t.Fatal(err)
	}
	tiers := CRSTiers(manifest, loadedCRSProfiles(t), crsSetOrder())
	names := []string{}
	for _, tier := range tiers {
		names = append(names, tier.PackID+"="+tier.Name)
	}
	if strings.Join(names, ",") != "system/crs-pl1-log=仅记录,system/crs-pl1=标准防护,system/crs-pl2=严格防护,system/crs-pl3=极严格防护" {
		t.Fatalf("tier order %v", names)
	}
	if tiers[0].Action != "log" || tiers[1].Action != "block" || len(tiers[0].Sets) != 5 || len(tiers[2].Sets) != 11 {
		t.Fatalf("tier shape %+v", tiers[:3])
	}
	for index := 1; index < len(tiers); index++ {
		before, tier := tiers[index-1], tiers[index]
		sets := map[string]CRSTierSet{}
		for _, set := range tier.Sets {
			sets[set.Key] = set
		}
		for _, set := range before.Sets {
			now, ok := sets[set.Key]
			if !ok || now.Paranoia < set.Paranoia {
				t.Fatalf("%s drops or lowers %s of %s", tier.PackID, set.Key, before.PackID)
			}
			for _, id := range set.Rules {
				if _, found := slices.BinarySearch(now.Rules, id); !found {
					t.Fatalf("%s no longer evaluates rule %d of %s", tier.PackID, id, set.Key)
				}
			}
		}
		if tier.Paranoia < before.Paranoia || len(tier.Added) == 0 || tier.Previous != before.PackID {
			t.Fatalf("%s adds nothing to %s: %+v", tier.PackID, before.PackID, tier)
		}
		for _, added := range tier.Added {
			if added.Rules <= 0 {
				t.Fatalf("%s empty addition %+v", tier.PackID, added)
			}
		}
	}
	// 严格防护 adds exactly the six classes 标准防护 lacks; the CRS SSTI and
	// deserialization classes are CRS's own rules (934180/934200, 944120/944200/944210/944240, 933170).
	added := []string{}
	for _, item := range tiers[2].Added {
		if item.Kind == "set" {
			added = append(added, item.Key)
		}
	}
	sort.Strings(added)
	if strings.Join(added, ",") != "waf_set:crs_generic,waf_set:crs_java_code_injection,waf_set:crs_java_deserialization,waf_set:crs_php_code_injection,waf_set:crs_php_deserialization,waf_set:crs_ssti" {
		t.Fatalf("严格防护 adds %v", added)
	}
	// waf-gap5: the rest of REQUEST-934 (Node.js / prototype pollution /
	// Ruby / Perl / data: / SSRF / ORM) up to the tier's paranoia
	generic := map[string]string{"system/crs-pl2": "934100,934101,934110,934120,934130,934140,934150,934160,934170,934190,934220",
		"system/crs-pl3": "934100,934101,934110,934120,934130,934140,934150,934160,934170,934190,934210,934220"}
	for _, tier := range tiers[2:] {
		for _, set := range tier.Sets {
			if set.Key == "waf_set:crs_generic" && intsJoin(set.Rules) != generic[tier.PackID] {
				t.Fatalf("%s crs_generic rules %v", tier.PackID, set.Rules)
			}
		}
	}
	for _, set := range tiers[2].Sets {
		want := map[string]string{"waf_set:crs_ssti": "934180,934200", "waf_set:crs_java_deserialization": "944120,944200,944210,944240",
			"waf_set:crs_php_deserialization": "933170"}[set.Key]
		if want != "" && intsJoin(set.Rules) != want {
			t.Fatalf("%s rules %v", set.Key, set.Rules)
		}
	}
	for _, tier := range tiers {
		t.Logf("%s %s action=%s PL%d sets=%d added=%+v", tier.PackID, tier.Name, tier.Action, tier.Paranoia, len(tier.Sets), tier.Added)
	}
}

func intsJoin(values []int) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}
