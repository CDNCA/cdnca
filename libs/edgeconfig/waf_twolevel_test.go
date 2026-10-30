package edgeconfig

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// twoLevelTestProfile is testCRSProfile with set 0 at paranoia 2 scoring in
// two levels (strong = PL1, weak threshold 10).
func standardTestProfile(digest string) CRSProfile {
	profile := testCRSProfile(digest)
	profile.Sets[0].Paranoia = 1
	manifest, _ := DeriveCRSManifest(testCRSRuleText())
	profile.Exports = nil
	for _, rule := range manifest.Rules {
		if (strings.HasPrefix(rule.File, "REQUEST-941-") || strings.HasPrefix(rule.File, "REQUEST-942-")) && rule.Paranoia <= 1 {
			profile.Exports = append(profile.Exports, rule.ID)
		}
	}
	return profile
}

func twoLevelTestProfile(digest string) CRSProfile {
	profile := testCRSProfile(digest)
	profile.Ref.PackID = "system/crs-strict"
	profile.Sets[0].Paranoia, profile.Sets[0].StrongParanoia, profile.Sets[0].WeakThreshold = 2, 1, 10
	profile.Sets[0].GreyAction, profile.Sets[0].Adaptive = ManagedWAFGreyChallenge, true
	return profile
}

// Two-level scoring (waf-strict-algo): PL1 rules keep scoring the strong sum
// with its threshold (the lower tier's decision is unchanged), higher
// paranoia rules score a weak sum, and the combined decision fires only for
// a two-level tier.
func TestDynamicWAFTwoLevelScoring(t *testing.T) {
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	release := dynamicTestRelease(t, standardTestProfile(testCRSProfileSHA256), strict)
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	set := strict.Sets[0]
	tx := managedSetTX(set.Key)
	manifest, _ := DeriveCRSManifest(testCRSRuleText())
	strong, weak := 0, 0
	for _, rule := range manifest.Rules {
		resolved, _ := resolveManagedSet(manifest, set)
		member := false
		for _, r := range resolved.Rules {
			member = member || r.ID == rule.ID
		}
		if !member {
			continue
		}
		weakLine := fmt.Sprintf("SecRuleUpdateActionById %d \"setvar:'tx.cdnca_%s_weak=+", rule.ID, tx)
		strongLine := fmt.Sprintf("SecRuleUpdateActionById %d \"setvar:'tx.cdnca_%s_score=+", rule.ID, tx)
		switch {
		case rule.Paranoia > 1 && strings.Contains(text, weakLine):
			weak++
		case rule.Paranoia <= 1 && strings.Contains(text, strongLine):
			strong++
		default:
			t.Fatalf("rule %d (PL%d) scores the wrong sum", rule.ID, rule.Paranoia)
		}
	}
	if strong == 0 || weak == 0 {
		t.Fatalf("strong %d weak %d", strong, weak)
	}
	for _, want := range []string{
		fmt.Sprintf("SecRule TX:cdnca_%s_score \"@ge %%{tx.cdnca_%s_threshold}\"", tx, tx),
		fmt.Sprintf("setvar:'tx.cdnca_%s_total=+%%{tx.cdnca_%s_weak}'", tx, tx),
		fmt.Sprintf("SecRule TX:cdnca_%s_total \"@ge %%{tx.cdnca_%s_weak_threshold}\"", tx, tx),
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node rules lack %q", want)
		}
	}
	// the tiers: the one-level tier's weak threshold is 0 (combined rules
	// never fire), the strict tier's is 10; both start the sums at 0
	for _, c := range []struct {
		profile CRSProfile
		weak    int
	}{{standardTestProfile(testCRSProfileSHA256), 0}, {strict, 10}} {
		site := *managedWAFTestSite().ManagedWAF
		site.Profile = c.profile.Ref
		tier, err := RenderDynamicWAFTier(release, site.TierOf())
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{fmt.Sprintf("setvar:tx.cdnca_%s_weak_threshold=%d", tx, c.weak),
			fmt.Sprintf("setvar:tx.cdnca_%s_score=0", tx), fmt.Sprintf("setvar:tx.cdnca_%s_weak=0", tx)} {
			if !strings.Contains(string(tier), want) {
				t.Fatalf("%s tier lacks %q", c.profile.Ref.PackID, want)
			}
		}
	}
}

func TestTwoLevelScoringValidation(t *testing.T) {
	manifest, _ := DeriveCRSManifest(testCRSRuleText())
	base := twoLevelTestProfile(strings.Repeat("d", 64)).Sets[0]
	if _, err := resolveManagedSet(manifest, base); err != nil {
		t.Fatalf("valid two-level set: %v", err)
	}
	for name, mutate := range map[string]func(*ManagedWAFSet){
		"strong without weak":      func(s *ManagedWAFSet) { s.WeakThreshold = 0 },
		"weak without strong":      func(s *ManagedWAFSet) { s.StrongParanoia = 0 },
		"strong at paranoia":       func(s *ManagedWAFSet) { s.StrongParanoia = 2 },
		"weak not above threshold": func(s *ManagedWAFSet) { s.WeakThreshold = s.Threshold },
		"weak too large":           func(s *ManagedWAFSet) { s.WeakThreshold = 1001 },
		"no grey action":           func(s *ManagedWAFSet) { s.GreyAction = "" },
		"grey action":              func(s *ManagedWAFSet) { s.GreyAction = "block" },
		"one-level grey":           func(s *ManagedWAFSet) { s.StrongParanoia, s.WeakThreshold = 0, 0 },
		"one-level adaptive": func(s *ManagedWAFSet) {
			s.StrongParanoia, s.WeakThreshold, s.GreyAction = 0, 0, ""
		},
		"strong rule order":  func(s *ManagedWAFSet) { s.StrongRules = []int{942200, 942100} },
		"strong rule twice":  func(s *ManagedWAFSet) { s.StrongRules = []int{942200, 942200} },
		"strong rule range":  func(s *ManagedWAFSet) { s.StrongRules = []int{42100} },
		"strong rule pl1":    func(s *ManagedWAFSet) { s.StrongRules = []int{firstRule(manifest, s, 1)} },
		"strong rule pl3":    func(s *ManagedWAFSet) { s.StrongRules = []int{firstRule(manifest, s, 3)} },
		"strong rule other":  func(s *ManagedWAFSet) { s.StrongRules = []int{941100} },
		"strong rules count": func(s *ManagedWAFSet) { s.StrongRules = make([]int, maxManagedWAFStrongRules+1) },
	} {
		set := base
		mutate(&set)
		if _, err := resolveManagedSet(manifest, set); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// a grey allow set without automation is valid; so is a one-level set
	// without any adaptive field
	allow := base
	allow.GreyAction, allow.Adaptive = ManagedWAFGreyAllow, false
	if _, err := resolveManagedSet(manifest, allow); err != nil {
		t.Fatalf("grey allow: %v", err)
	}
	// one sum per rule and set key on a node: two-level tiers of a key split
	// at one level, and no one-level tier of that key reads above it
	a := twoLevelTestProfile(strings.Repeat("d", 64))
	b := twoLevelTestProfile(strings.Repeat("f", 64))
	b.Ref.PackID = "system/crs-strict3"
	b.Sets[0].Paranoia, b.Sets[0].StrongParanoia = 3, 2
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{a, b}); err == nil {
		t.Fatal("two splits of one set key accepted")
	}
	// ... and agree on the reweighted rules
	b = twoLevelTestProfile(strings.Repeat("f", 64))
	b.Ref.PackID = "system/crs-strict3"
	b.Sets[0].StrongRules = []int{firstRule(manifest, &b.Sets[0], 2)}
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{a, b}); err == nil {
		t.Fatal("two reweightings of one set key accepted")
	}
	c := testCRSProfile(strings.Repeat("a", 64))
	c.Sets[0].Paranoia = 2
	c.Exports = nil
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{a, c}); err == nil {
		t.Fatal("one-level PL2 tier next to a two-level split at PL1 accepted")
	}
}

// firstRule is the first member of set at paranoia level.
func firstRule(manifest *CRSManifest, set *ManagedWAFSet, level int) int {
	plain := *set
	plain.StrongRules = nil
	resolved, _ := resolveManagedSet(manifest, plain)
	for _, rule := range resolved.Rules {
		if rule.Paranoia == level {
			return rule.ID
		}
	}
	return 0
}

// TestStrongRulesScoreStrong: a reweighted PL2 rule of a two-level set
// scores the strong sum; the other PL2 rules stay weak.
func TestStrongRulesScoreStrong(t *testing.T) {
	manifest, _ := DeriveCRSManifest(testCRSRuleText())
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	id := firstRule(manifest, &strict.Sets[0], 2)
	other := 0
	plain := strict.Sets[0]
	resolved, _ := resolveManagedSet(manifest, plain)
	for _, rule := range resolved.Rules {
		if rule.Paranoia == 2 && rule.ID != id {
			other = rule.ID
			break
		}
	}
	if id == 0 || other == 0 {
		t.Fatal("test rule text needs two PL2 rules in set 0")
	}
	strict.Sets[0].StrongRules = []int{id}
	release := dynamicTestRelease(t, strict)
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	tx := managedSetTX(strict.Sets[0].Key)
	text := string(rules)
	if !strings.Contains(text, fmt.Sprintf("SecRuleUpdateActionById %d \"setvar:'tx.cdnca_%s_score=+", id, tx)) ||
		!strings.Contains(text, fmt.Sprintf("SecRuleUpdateActionById %d \"setvar:'tx.cdnca_%s_weak=+", other, tx)) {
		t.Fatalf("rule %d is not strong or %d not weak", id, other)
	}
}

// Detector signals (waf-strict-algo 2b): one rule per detector whose set a
// profile on the node has, adding a critical score to that set's strong sum
// only when the request's tier scores the set in two levels; the two-level
// profiles are the ones whose sites Lua computes the verdicts for.
func TestDynamicWAFDetectorSignals(t *testing.T) {
	standard := standardTestProfile(testCRSProfileSHA256)
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	for _, profile := range []*CRSProfile{&standard, &strict} {
		profile.Sets[0].Key, profile.Sets[1].Key = "waf_set:crs_sqli", "waf_set:crs_xss"
	}
	release := dynamicTestRelease(t, standard, strict)
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	for _, want := range []string{
		`SecRule TX:cdnca_detect "@contains ,sqli," "id:30080,phase:2,pass,log,auditlog,t:none,msg:'cdnca waf detector sqli',tag:'cdnca/waf_set:crs_sqli',chain"`,
		`  SecRule TX:cdnca_crs_sqli_weak_threshold "@gt 0" "t:none,setvar:'tx.cdnca_crs_sqli_score=+5'"`,
		`SecRule TX:cdnca_detect "@contains ,xss," "id:30081,`,
		"setvar:tx.cdnca_intel=%{TX.6},setvar:tx.cdnca_detect=%{TX.7},setvar:tx.cdnca_grey_floor=%{TX.8}", "setvar:tx.cdnca_tuning_off=%{TX.2},setvar:tx.cdnca_exclude=%{TX.3}",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node rules lack %q", want)
		}
	}
	// no profile has the other detectors' sets
	for _, absent := range []string{",ssti,", ",java_deser,", ",php_deser,"} {
		if strings.Contains(text, absent) {
			t.Fatalf("node rules score detector %s without its set", absent)
		}
	}
	if got := release.TwoLevelProfiles(); len(got) != 1 || got[0] != strict.Ref.SHA256 {
		t.Fatalf("two-level profiles %v", got)
	}
	// 标准防护's tier sets the weak threshold to 0: the signal never adds
	tier, err := RenderDynamicWAFTier(release, DynamicWAFTier{Profile: standard.Ref, RequestBodyLimit: 1 << 20,
		RequestBodyNoFilesLimit: 1 << 17, RequestBodyLimitAction: "reject", ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tier), "setvar:tx.cdnca_crs_sqli_weak_threshold=0") {
		t.Fatalf("standard tier: %s", tier)
	}
}

// waf-cookie-fp: a two-level tier's weak rules do not inspect cookies;
// strong rules (标准防护's PL1) keep them. waf-cookie-fp2: the tier's cookie
// variant (entered for a cookie out of the site's profile) keeps them for
// the weak rules too; a one-level tier has neither the change nor a variant,
// and the node rules carry no target change at all.
func TestDynamicWAFWeakRulesSkipCookies(t *testing.T) {
	manifest, _ := DeriveCRSManifest(testCRSRuleText())
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	standard := standardTestProfile(testCRSProfileSHA256)
	release := dynamicTestRelease(t, standard, strict)
	tierOf := func(profile CRSProfile) DynamicWAFTier {
		return DynamicWAFTier{Profile: profile.Ref, RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 1 << 17,
			RequestBodyLimitAction: "reject", ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 1000}
	}
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rules), "SecRuleUpdateTargetById") {
		t.Fatal("node rules change rule targets")
	}
	tier, err := RenderDynamicWAFTier(release, tierOf(strict))
	if err != nil {
		t.Fatal(err)
	}
	variant, err := RenderDynamicWAFTierCookies(release, tierOf(strict))
	if err != nil {
		t.Fatal(err)
	}
	if !release.TwoLevel(tierOf(strict)) || release.TwoLevel(tierOf(standard)) {
		t.Fatal("TwoLevel")
	}
	weak, strong := 0, 0
	for _, set := range strict.Sets {
		resolved, _ := resolveManagedSet(manifest, set)
		for _, rule := range resolved.Rules {
			line := fmt.Sprintf("SecRuleUpdateTargetById %d \"!REQUEST_COOKIES|!REQUEST_COOKIES_NAMES\"\n", rule.ID)
			evaluated := rule.Paranoia <= set.Paranoia
			if (evaluated && set.weakRule(rule)) != strings.Contains(string(tier), line) {
				t.Fatalf("rule %d (PL%d, weak %t): cookie target line wrong", rule.ID, rule.Paranoia, set.weakRule(rule))
			}
			if strings.Contains(string(variant), line) {
				t.Fatalf("cookie variant drops cookies of rule %d", rule.ID)
			}
			if evaluated && set.weakRule(rule) {
				weak++
			} else if evaluated {
				strong++
			}
		}
	}
	if weak == 0 || strong == 0 {
		t.Fatalf("weak %d strong %d", weak, strong)
	}
	// the variant is the tier otherwise
	if tier == nil || string(tier) == string(variant) || !strings.HasPrefix(string(tier), string(variant)) {
		t.Fatal("cookie variant is not the tier without the cookie target changes")
	}
	plain, err := RenderDynamicWAFTier(release, tierOf(standard))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "SecRuleUpdateTargetById") {
		t.Fatal("a one-level tier changes rule targets")
	}
	if _, err := RenderDynamicWAFTierCookies(release, tierOf(standard)); err == nil {
		t.Fatal("a one-level tier has a cookie variant")
	}
}

// TestWeakWeights (waf-gap6 S1, research §3.1): a two-level set's learned
// weights replace a weak rule's severity in its weak sum (fixed integers,
// learned offline, part of the profile pack); 0 = the rule only logs. Only
// weak rules, only below their severity (nothing gets stricter or relaxes
// a strong rule), ascending, the same on every two-level set of the key.
func TestWeakWeights(t *testing.T) {
	manifest, _ := DeriveCRSManifest(testCRSRuleText())
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	weak, other := firstRule(manifest, &strict.Sets[0], 2), 0
	resolved, _ := resolveManagedSet(manifest, strict.Sets[0])
	for _, rule := range resolved.Rules {
		if rule.Paranoia == 2 && rule.ID != weak && other == 0 {
			other = rule.ID
		}
	}
	if weak == 0 || other == 0 {
		t.Fatal("test rule text needs two PL2 rules in set 0")
	}
	strict.Sets[0].WeakWeights = []ManagedWAFWeight{{Rule: weak, Weight: 2}, {Rule: other, Weight: 0}}
	release := dynamicTestRelease(t, standardTestProfile(testCRSProfileSHA256), strict)
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	tx := managedSetTX(strict.Sets[0].Key)
	if !strings.Contains(text, fmt.Sprintf("SecRuleUpdateActionById %d \"setvar:'tx.cdnca_%s_weak=+2'\"\n", weak, tx)) {
		t.Fatalf("rule %d does not score its learned weight 2", weak)
	}
	if strings.Contains(text, fmt.Sprintf("SecRuleUpdateActionById %d ", other)) {
		t.Fatalf("weight 0 rule %d still scores", other)
	}
	strongRule := firstRule(manifest, &strict.Sets[0], 1)
	severity := 0
	for _, rule := range manifest.Rules {
		if rule.ID == weak {
			severity = map[string]int{"critical": 5, "error": 4, "warning": 3, "notice": 2}[rule.Severity]
		}
	}
	for name, weights := range map[string][]ManagedWAFWeight{
		"strong rule":   {{Rule: strongRule, Weight: 1}},
		"not a member":  {{Rule: 941100, Weight: 1}},
		"at severity":   {{Rule: weak, Weight: severity}},
		"negative":      {{Rule: weak, Weight: -1}},
		"order":         {{Rule: other, Weight: 1}, {Rule: weak, Weight: 1}},
		"twice":         {{Rule: weak, Weight: 1}, {Rule: weak, Weight: 1}},
		"reweighted":    {{Rule: weak, Weight: 1}},
		"one-level set": {{Rule: weak, Weight: 1}},
	} {
		set := strict.Sets[0]
		set.WeakWeights = weights
		if name == "order" && other < weak || name == "twice" {
			// "order" needs the larger ID first
			if name == "order" {
				set.WeakWeights = []ManagedWAFWeight{{Rule: max(weak, other), Weight: 1}, {Rule: min(weak, other), Weight: 1}}
			}
		}
		if name == "reweighted" {
			set.StrongRules = []int{weak}
		}
		if name == "one-level set" {
			set.StrongParanoia, set.WeakThreshold, set.GreyAction, set.Adaptive = 0, 0, "", false
		}
		if _, err := resolveManagedSet(manifest, set); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// the same key splits the same way on every two-level tier of a node
	extreme := twoLevelTestProfile(strings.Repeat("e", 64))
	extreme.Ref.PackID = "system/crs-extreme"
	extreme.Sets[0].Paranoia = 3
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{strict, extreme}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("different weights for one set key accepted: %v", err)
	}
	extreme.Sets[0].WeakWeights = strict.Sets[0].WeakWeights
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{strict, extreme}); err != nil {
		t.Fatalf("same weights refused: %v", err)
	}
	// waf-gap7: 严格防护 (PL2) and 极严格防护 (PL3) carry one weight list per
	// set key, so a PL3 rule's weight is in the PL2 set too (inert there: the
	// tier does not run PL3 rules)
	pl3 := firstRule(manifest, &extreme.Sets[0], 3)
	if pl3 == 0 {
		t.Fatal("test rule text needs a PL3 rule in set 0")
	}
	shared := []ManagedWAFWeight{{Rule: min(weak, pl3), Weight: 1}, {Rule: max(weak, pl3), Weight: 1}}
	strict.Sets[0].WeakWeights, extreme.Sets[0].WeakWeights = shared, shared
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{strict, extreme}); err != nil {
		t.Fatalf("a PL3 rule's weight in the PL2 set refused: %v", err)
	}
}
