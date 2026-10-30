package securitypolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
)

func seedCatalog() map[string]rulecatalog.Item {
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CurrentSeed() {
		items[item.SystemKey] = item
	}
	return items
}

func expandedPolicy(t *testing.T, items map[string]rulecatalog.Item, key string) Policy {
	t.Helper()
	rules, err := ExpandCCRuleGroup(items, key)
	if err != nil {
		t.Fatalf("ExpandCCRuleGroup(%s): %v", key, err)
	}
	for index := range rules {
		rules[index].ID = uuid.New()
	}
	return Policy{ID: uuid.New(), ScopeID: uuid.New(), Kind: KindCC, Name: key, Enabled: true,
		DefaultAction: ActionAllow, Revision: 1, Rules: rules}
}

func TestExpandCCRuleGroupEveryCatalogGroupIsPublishable(t *testing.T) {
	items := seedCatalog()
	groups := 0
	for key, item := range items {
		if item.Kind != rulecatalog.KindCCRuleGroup || len(item.Body.CCRuleGroup.Entries) == 0 {
			continue
		}
		groups++
		if err := ValidatePublishablePolicy(expandedPolicy(t, items, key)); err != nil {
			t.Errorf("%s %s: %v", key, item.Name, err)
		}
	}
	if groups != 13 {
		t.Fatalf("expanded %d rule groups, want the 13 non-empty seed groups (3 rate-trigger templates)", groups)
	}
}

func TestExpandCCRuleGroupFiveSecondShieldSemantics(t *testing.T) {
	rules, err := ExpandCCRuleGroup(seedCatalog(), "cc_rule:10001")
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%d err=%v", len(rules), err)
	}
	rule := rules[0]
	// Every value is the catalog's: filter cc_filter:10001 (60-5 and its
	// params) and the hidden whitelist filter cc_filter:11 (5-300-50).
	want := ChallengeConfig{Type: "five_second", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 21600,
		BanSeconds: 360, PowBits: 18, DelaySeconds: 5, ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64,
		KeyRotateSeconds: 86400, PassWindowSeconds: 5, PassMaxRequests: 300, PassMaxRequestsPerURI: 50}
	if rule.Action != ActionChallenge || rule.Flow != FlowStop || rule.ActionConfig.Challenge == nil ||
		*rule.ActionConfig.Challenge != want || len(rule.Conditions) != 1 || rule.Conditions[0].Values[0] != "/" {
		t.Fatalf("5秒盾 = %+v challenge=%+v", rule, rule.ActionConfig.Challenge)
	}
}

func TestExpandCCRuleGroupRelaxedIsRateWithPerURIAndBlacklist(t *testing.T) {
	rules, err := ExpandCCRuleGroup(seedCatalog(), "cc_rule:6")
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%d err=%v", len(rules), err)
	}
	want := RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: 5, MaxRequests: 300, MaxPerURI: 50,
		ResponseAction: "temporary_ban", BanSeconds: 360}
	if limit := rules[0].ActionConfig.RateLimit; limit == nil || *limit != want {
		t.Fatalf("宽松 = %+v", rules[0].ActionConfig.RateLimit)
	}
}

// TestExpandCCRuleGroupRateThenChallenge: filter1 请求速率 + filter2 验证 is
// one challenge rule of filter2 that only triggers above filter1's rate
// (competitor "两者都失败才执行动作"); failing the page blacklists.
func TestExpandCCRuleGroupRateThenChallenge(t *testing.T) {
	items := seedCatalog()
	for key, mode := range map[string]string{"cc_rule:rate_then_js": "js", "cc_rule:rate_then_slider": "slider",
		"cc_rule:rate_then_five_second": "five_second"} {
		rules, err := ExpandCCRuleGroup(items, key)
		if err != nil || len(rules) != 1 {
			t.Fatalf("%s rules=%d err=%v", key, len(rules), err)
		}
		challenge := rules[0].ActionConfig.Challenge
		if rules[0].Action != ActionChallenge || rules[0].Flow != FlowStop || challenge == nil || challenge.Type != mode ||
			challenge.TriggerWindowSeconds != 5 || challenge.TriggerMaxRequests != 100 || challenge.BanSeconds != 360 ||
			challenge.FailureWindowSeconds != 60 || challenge.MaxFailures != 5 || challenge.PassMaxRequests != 300 {
			t.Fatalf("%s = %+v challenge=%+v", key, rules[0], challenge)
		}
		policy := expandedPolicy(t, items, key)
		if err := ValidatePublishablePolicy(policy); err != nil {
			t.Fatalf("%s refused: %v", key, err)
		}
	}
	rules, _ := ExpandCCRuleGroup(items, "cc_rule:rate_then_js")
	if want := "超限转JS验证 · 请求速率5-100 → 浏览器识别60-5"; rules[0].Name != want {
		t.Fatalf("name = %q, want %q", rules[0].Name, want)
	}
	// Disabled filter2 entries are skipped like any other entry.
	group := items["cc_rule:rate_then_js"]
	body := *group.Body.CCRuleGroup
	body.Entries = append([]rulecatalog.CCRuleGroupEntry(nil), body.Entries...)
	body.Entries[0].Enabled = false
	group.Body.CCRuleGroup = &body
	items["cc_rule:test"] = group
	if rules, err := ExpandCCRuleGroup(items, "cc_rule:test"); err != nil || len(rules) != 0 {
		t.Fatalf("disabled entry rules=%v err=%v", rules, err)
	}
}

func TestExpandCCRuleGroupStaticMatcherAndFailClosed(t *testing.T) {
	items := seedCatalog()
	group := items["cc_rule:10001"]
	body := *group.Body.CCRuleGroup
	body.Entries = append([]rulecatalog.CCRuleGroupEntry(nil), body.Entries...)
	body.Entries[0].MatcherKey = "cc_matcher:4"
	group.Body.CCRuleGroup = &body
	items["cc_rule:test"] = group
	rules, err := ExpandCCRuleGroup(items, "cc_rule:test")
	if err != nil || rules[0].Conditions[0].Operator != "contains" || len(rules[0].Conditions[0].Values) != 6 {
		t.Fatalf("static matcher rules=%+v err=%v", rules, err)
	}
	// filter2 needs filter1 = req_rate without a per-URI budget and a
	// verification filter2; any other pair fails closed.
	for _, pair := range [][2]string{{"cc_filter:10001", "cc_filter:1"}, {"cc_filter:9", "cc_filter:8"},
		{"cc_filter:rate_trigger_5_100", "cc_filter:9"}, {"cc_filter:rate_trigger_5_100", "cc_filter:missing"}} {
		body.Entries[0].Filter1Key, body.Entries[0].Filter2Key = pair[0], pair[1]
		if _, err := ExpandCCRuleGroup(items, "cc_rule:test"); !errors.Is(err, ErrCatalogUnsupported) {
			t.Fatalf("filters %v err=%v, want ErrCatalogUnsupported", pair, err)
		}
	}
	if _, err := ExpandCCRuleGroup(items, "cc_rule:missing"); !errors.Is(err, ErrCatalogUnsupported) {
		t.Fatalf("missing group err=%v", err)
	}
}

func TestExpandWAFRuleSetsEveryCatalogSetIsPublishable(t *testing.T) {
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.BuiltinWAFSeed() {
		items[item.SystemKey] = item
	}
	for key := range items {
		for _, action := range []string{"", ActionLog, ActionBlock} {
			rules, err := ExpandWAFRuleSets(items, []string{key}, action)
			if err != nil {
				t.Fatalf("%s %q: %v", key, action, err)
			}
			for index := range rules {
				rules[index].ID = uuid.New()
			}
			policy := Policy{ID: uuid.New(), ScopeID: uuid.New(), Kind: KindWAF, Name: key, Enabled: true,
				DefaultAction: ActionAllow, Revision: 1, Rules: rules}
			if err := ValidatePublishablePolicy(policy); err != nil {
				t.Errorf("%s %q: %v", key, action, err)
			}
		}
	}
	rules, _ := ExpandWAFRuleSets(items, []string{"waf_set:sqli"}, ActionBlock)
	if rules[0].Conditions[0].Operator != "detect" || rules[0].Action != ActionBlock || rules[0].Flow != FlowStop {
		t.Fatalf("sqli detector rule = %+v", rules[0])
	}
	// SSTI and the two deserialization sets carry their own node detectors.
	for key, detector := range map[string]string{"waf_set:ssti": "ssti", "waf_set:java_deserialization": "java_deser",
		"waf_set:php_deserialization": "php_deser"} {
		rules, _ := ExpandWAFRuleSets(items, []string{key}, ActionBlock)
		if rules[0].Conditions[0].Operator != "detect" || rules[0].Conditions[0].Values[0] != detector {
			t.Fatalf("%s detector rule = %+v", key, rules[0])
		}
	}
	if _, err := ExpandWAFRuleSets(items, []string{"waf_set:sqli"}, "allow"); err == nil {
		t.Fatal("allow override accepted")
	}
}

func TestCatalogWAFRulesRunsSelfDevelopedAndCRSSideBySide(t *testing.T) {
	items := rulecatalog.CurrentSeed()
	both, err := CatalogWAFRules(items, []string{"waf_set:sqli", "waf_set:xss", "waf_set:crs_sqli", "waf_set:crs_xss"})
	if err != nil {
		t.Fatal(err)
	}
	managed, detectors := 0, map[string]bool{}
	for index, rule := range both {
		if rule.Priority != index+1 {
			t.Fatalf("rule %d priority %d", index, rule.Priority)
		}
		if rule.Action == ActionManagedWAF {
			managed++
			if index != len(both)-1 || rule.ActionConfig.ManagedWAF.Profile != DefaultCRSProfile {
				t.Fatalf("managed rule = %+v at %d", rule.ActionConfig.ManagedWAF, index)
			}
			continue
		}
		for _, condition := range rule.Conditions {
			if condition.Operator == "detect" {
				detectors[condition.Values[0]] = true
			}
		}
	}
	if managed != 1 || !detectors["sqli"] || !detectors["xss"] {
		t.Fatalf("managed=%d detectors=%v", managed, detectors)
	}
	for index := range both {
		both[index].ID = uuid.New()
	}
	policy := Policy{ID: uuid.New(), ScopeID: uuid.New(), Kind: KindWAF, Name: "both", Enabled: true,
		DefaultAction: ActionAllow, Revision: 1, Rules: both}
	if err := ValidatePublishablePolicy(policy); err != nil {
		t.Fatal(err)
	}
	selfOnly, err := CatalogWAFRules(items, []string{"waf_set:sqli"})
	if err != nil || len(selfOnly) == 0 {
		t.Fatalf("self-developed only = %d, %v", len(selfOnly), err)
	}
	for _, rule := range selfOnly {
		if rule.Action == ActionManagedWAF {
			t.Fatal("self-developed import added the CRS engine")
		}
	}
	crsOnly, err := CatalogWAFRules(items, []string{"waf_set:crs_sqli"})
	if err != nil || len(crsOnly) != 1 || crsOnly[0].Action != ActionManagedWAF {
		t.Fatalf("CRS only = %+v, %v", crsOnly, err)
	}
	for _, keys := range [][]string{{"waf_set:crs_rules"}, {"waf_set:crs_settings"}, {"waf_set:sqli", "waf_set:sqli"}, {"cc_rule:1"}} {
		if _, err := CatalogWAFRules(items, keys); !errors.Is(err, ErrCatalogUnsupported) {
			t.Fatalf("%v err = %v", keys, err)
		}
	}
	if catalog := NewManagedWAFCatalog(items); catalog.Rules == nil || catalog.Rules.Version != "4.30.0" {
		t.Fatalf("catalog rule text = %+v", catalog.Rules)
	}
}

func managedTestCatalog() ManagedWAFCatalog {
	return NewManagedWAFCatalog(rulecatalog.CurrentSeed())
}

// testCRSProfiles are the system/crs-* packs as libs/rulepack generates them
// (its goldens, the bytes license migration 087 seeds).
func testCRSProfiles(t *testing.T) CRSProfiles {
	t.Helper()
	paths, err := filepath.Glob("../../../../libs/rulepack/testdata/crs-profiles/crs-*.json")
	if err != nil || len(paths) != 4 {
		t.Fatalf("CRS profile goldens: %v %v", paths, err)
	}
	profiles := CRSProfiles{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		compiled, profile, err := rulepack.LoadCRSProfile(content, hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		profiles[profile.Ref.PackID] = CRSProfile{Profile: profile, Content: content, Description: compiled.Pack.Description}
	}
	return profiles
}

func TestManagedWAFDefaultsComeFromCatalogAndArePublishable(t *testing.T) {
	catalog := managedTestCatalog()
	if catalog.Settings == nil || catalog.Rules == nil {
		t.Fatalf("catalog settings=%v rules=%v", catalog.Settings, catalog.Rules)
	}
	config, err := ManagedWAFDefaults(catalog, DefaultCRSProfile)
	if err != nil {
		t.Fatal(err)
	}
	if config.RequestBodyLimit != catalog.Settings.RequestBodyLimit || config.RequestBodyLimitAction != "reject" ||
		config.Profile != DefaultCRSProfile || len(config.Exclusions) != 0 {
		t.Fatalf("defaults = %+v", config)
	}
	if err := testCRSProfiles(t).Check(config); err != nil {
		t.Fatalf("default profile not among the generated packs: %v", err)
	}
	rule := Rule{ID: uuid.New(), Name: "托管规则集", Priority: 1, Enabled: true, Action: ActionManagedWAF,
		Flow: FlowContinue, Conditions: []Condition{}, ActionConfig: ActionConfig{ManagedWAF: &config}}
	policy := Policy{ID: uuid.New(), ScopeID: uuid.New(), Kind: KindWAF, Name: "managed", Enabled: true,
		DefaultAction: ActionAllow, Revision: 1, Rules: []Rule{rule}}
	if err := ValidatePublishablePolicy(policy); err != nil {
		t.Fatal(err)
	}
	policy.Kind = KindCC
	if err := ValidatePublishablePolicy(policy); err == nil {
		t.Fatal("managed_waf accepted in a CC policy")
	}
	if _, err := ManagedWAFDefaults(catalog, "system/sqli"); err == nil {
		t.Fatal("non CRS profile pack accepted")
	}
}

// PA-12: a managed WAF names a profile pack and excludes only rules the
// profile exports; the exclusion list is sorted and unique.
func TestManagedWAFProfileAndExclusions(t *testing.T) {
	profiles := testCRSProfiles(t)
	config, err := ManagedWAFDefaults(managedTestCatalog(), "system/crs-pl2")
	if err != nil {
		t.Fatal(err)
	}
	config.Exclusions = []int{913100}
	if err := profiles.Check(config); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("913100 (not exported) err = %v", err)
	}
	config.Exclusions = []int{941100, 942100}
	if err := ValidateManagedWAF(config); err != nil || profiles.Check(config) != nil {
		t.Fatalf("exported exclusions rejected: %v", err)
	}
	for _, bad := range [][]int{{942100, 941100}, {942100, 942100}, {100}} {
		config.Exclusions = bad
		if ValidateManagedWAF(config) == nil {
			t.Fatalf("exclusions %v accepted", bad)
		}
	}
	config.Exclusions, config.Profile = nil, "system/crs-pl9"
	if err := profiles.Check(config); !errors.Is(err, ErrCRSProfileUnavailable) {
		t.Fatalf("missing profile err = %v", err)
	}
	edge := EdgeManagedWAF(config, profiles["system/crs-pl1"].Profile.Ref, managedWAFValidationPolicyID, 1, []string{"192.0.2.0/24"})
	if edge.Profile != profiles["system/crs-pl1"].Profile.Ref || len(edge.AllowCIDRs) != 1 {
		t.Fatalf("edge = %+v", edge)
	}
}

func TestCRSOverrideInheritsOrReplaces(t *testing.T) {
	library := ManagedWAFConfig{Profile: DefaultCRSProfile, Exclusions: []int{942100}}
	if got := EffectiveManagedWAF(library, CRSOverride{}); got.Profile != DefaultCRSProfile || !slices.Equal(got.Exclusions, []int{942100}) {
		t.Fatalf("inherit = %+v", got)
	}
	profile, none := "system/crs-pl2", []int{}
	got := EffectiveManagedWAF(library, CRSOverride{Profile: &profile, Exclusions: &none})
	if got.Profile != profile || len(got.Exclusions) != 0 {
		t.Fatalf("override = %+v", got)
	}
	ids := []int{942100, 941100}
	override := CRSOverride{Exclusions: &ids}
	if err := NormalizeCRSOverride(&override); err != nil || !slices.Equal(*override.Exclusions, []int{941100, 942100}) {
		t.Fatalf("normalize = %v %v", override.Exclusions, err)
	}
	for _, raw := range []string{`{}`, `{"profile":null,"exclusions":null}`, `{"profile":"system/sqli"}`,
		`{"exclusions":[1]}`, `{"exclusions":[942100,942100]}`, `{"other":1}`} {
		if _, err := DecodeCRSOverride([]byte(raw)); err == nil {
			t.Fatalf("%s decoded", raw)
		}
	}
	decoded, err := DecodeCRSOverride([]byte(`{"profile":"system/crs-pl3","exclusions":null}`))
	if err != nil || *decoded.Profile != "system/crs-pl3" || decoded.Exclusions != nil {
		t.Fatalf("decoded = %+v %v", decoded, err)
	}
}

// FX12: 检查上限动作默认只记录（目录不带该值），站点可改为 block，节点配置照传；其他值保存即拒绝。
func TestManagedWAFInspectionLimitActionDefaultsToLogAndPassesThrough(t *testing.T) {
	config, err := ManagedWAFDefaults(managedTestCatalog(), DefaultCRSProfile)
	if err != nil {
		t.Fatal(err)
	}
	if config.InspectionLimitAction != "" {
		t.Fatalf("default inspection limit action = %q, want empty (log)", config.InspectionLimitAction)
	}
	ref := testCRSProfiles(t)[DefaultCRSProfile].Profile.Ref
	for _, action := range []string{"", "log", "block"} {
		config.InspectionLimitAction = action
		if err := ValidateManagedWAF(config); err != nil {
			t.Fatalf("%q: %v", action, err)
		}
		if edge := EdgeManagedWAF(config, ref, managedWAFValidationPolicyID, 1, nil); edge.InspectionLimitAction != action {
			t.Fatalf("%q: edge inspection limit action = %q", action, edge.InspectionLimitAction)
		}
	}
	config.InspectionLimitAction = "drop"
	if ValidateManagedWAF(config) == nil {
		t.Fatal("unknown inspection limit action accepted")
	}
}

func TestExpandCCRuleGroupFollowsCatalogParameters(t *testing.T) {
	items := seedCatalog()
	filter := items["cc_filter:10001"]
	body := *filter.Body.CCFilter
	params := *body.Params
	params.PowBits, params.BanSeconds, params.PassSeconds, params.KeyRotateSeconds = 22, 1200, 3600, 7200
	body.Params, body.WithinSecond, body.MaxReq = &params, 30, 3
	filter.Body.CCFilter = &body
	items["cc_filter:10001"] = filter
	rules, err := ExpandCCRuleGroup(items, "cc_rule:10001")
	if err != nil {
		t.Fatal(err)
	}
	got := rules[0].ActionConfig.Challenge
	if got.PowBits != 22 || got.BanSeconds != 1200 || got.PassSeconds != 3600 || got.KeyRotateSeconds != 7200 ||
		got.FailureWindowSeconds != 30 || got.MaxFailures != 3 {
		t.Fatalf("challenge = %+v", got)
	}
	params.PowBits = 0 // explicit params are the catalog's and must be valid
	body.Params = &params
	items["cc_filter:10001"] = filter
	if _, err := ExpandCCRuleGroup(items, "cc_rule:10001"); !errors.Is(err, ErrCatalogUnsupported) {
		t.Fatalf("filter with invalid params err = %v", err)
	}
}

// A license service older than migration 065 (1.0.33, the deployed
// c37b9994), and any license service serving a control release below
// rulecatalog.EngineCatalogControlVersion, delivers CC filters without
// params. Every rule group must still expand with the platform defaults the
// competitor documents (blacklist 360 s, pass 21600 s) and the proof-of-work
// defaults of the filter type.
func TestExpandCCRuleGroupLegacyCatalogWithoutParams(t *testing.T) {
	items := map[string]rulecatalog.Item{}
	for _, item := range append(rulecatalog.CompetitorSeed(), rulecatalog.BuiltinWAFSeed()...) {
		if item.Body.CCFilter != nil && item.Body.CCFilter.Params != nil {
			t.Fatalf("legacy seed %s carries params", item.SystemKey)
		}
		items[item.SystemKey] = item
	}
	groups := 0
	for key, item := range items {
		if item.Kind != rulecatalog.KindCCRuleGroup || len(item.Body.CCRuleGroup.Entries) == 0 {
			continue
		}
		groups++
		if err := ValidatePublishablePolicy(expandedPolicy(t, items, key)); err != nil {
			t.Errorf("%s %s: %v", key, item.Name, err)
		}
	}
	if groups != 10 {
		t.Fatalf("expanded %d legacy rule groups, want 10", groups)
	}
	rules, err := ExpandCCRuleGroup(items, "cc_rule:10001")
	if err != nil {
		t.Fatal(err)
	}
	want := ChallengeConfig{Type: "five_second", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 21600,
		BanSeconds: 360, PowBits: 18, DelaySeconds: 5, ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64,
		KeyRotateSeconds: 86400, PassWindowSeconds: 5, PassMaxRequests: 300, PassMaxRequestsPerURI: 50}
	if got := rules[0].ActionConfig.Challenge; got == nil || *got != want {
		t.Fatalf("legacy 5秒盾 = %+v", got)
	}
	rules, err = ExpandCCRuleGroup(items, "cc_rule:6")
	if err != nil || rules[0].ActionConfig.RateLimit == nil || rules[0].ActionConfig.RateLimit.BanSeconds != 360 {
		t.Fatalf("legacy 宽松 = %+v, %v", rules, err)
	}
}
