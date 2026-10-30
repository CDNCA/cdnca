package edgeconfig

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Adaptive WAF node rules (ADR 0011 RI-03): tightening, shape, the grey
// zone (from the site's floor f=) and its challenge only for a tier whose
// set challenges, audit sampling by transaction, unique rule IDs; no
// automatic exclusion in the node rules (they are per site files).
func TestDynamicWAFAdaptiveRules(t *testing.T) {
	standard := standardTestProfile(testCRSProfileSHA256)
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	release := dynamicTestRelease(t, standard, strict)
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	tx := managedSetTX(strict.Sets[0].Key)
	for _, want := range []string{
		"SecAuditEngine Off\n", "setvar:tx.cdnca_grey_floor=%{TX.8}",
		"  SecRule TX:cdnca_" + tx + "_total \"@gt 0\" \"t:none,chain\"\n  SecRule TX:cdnca_" + tx + "_total \"@ge %{tx.cdnca_grey_floor}\" \"t:none,chain\"\n",
		`SecRule TX:cdnca_tighten "@contains ,` + strings.TrimPrefix(strict.Sets[0].Key, "waf_set:") + `,"`,
		"setvar:'tx.cdnca_" + tx + "_score=+%{tx.cdnca_" + tx + "_weak}',setvar:tx.cdnca_" + tx + "_weak=0",
		`SecRule TX:cdnca_detect "@contains ,shape,"`, "  SecRule TX:cdnca_" + tx + "_weak_threshold \"@gt 0\" \"t:none,setvar:'tx.cdnca_" + tx + "_weak=+5'\"",
		"SecRule TX:cdnca_" + tx + "_grey \"@eq 1\"", "setvar:tx.cdnca_grey_challenge=+1",
		`SecRule TX:cdnca_grey_challenge "@gt 0" "id:31995,phase:2,deny,status:599,`,
		`  SecRule TX:cdnca_grey_passed "@streq 0" "t:none,chain"`, `  SecRule TX:cdnca_browser "@streq 1" "t:none"`,
		`SecRule TX:cdnca_grey "@gt 0" "id:31996,phase:5,`, `  SecRule UNIQUE_ID "@rx 0$" "t:none,ctl:auditEngine=On,ctl:auditLogParts=-B"`,
		`SecRule TX:cdnca_decided "@eq 1" "id:31997,phase:5,pass,nolog,t:none,ctl:auditEngine=On"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node rules lack %q", want)
		}
	}
	// grey zone and tightening run after CRS and before the decisions;
	// the challenge after the decisions
	shape, decide, challenge := strings.Index(text, "@contains ,shape,"), strings.Index(text, "\"id:30100,phase:2,deny"),
		strings.Index(text, "id:31995,")
	if shape < strings.Index(text, "Include crs/REQUEST-942") || decide < shape || challenge < decide {
		t.Fatalf("order shape %d decide %d challenge %d", shape, decide, challenge)
	}
	ids := map[string]bool{}
	for _, match := range regexp.MustCompile(`"id:([0-9]+),`).FindAllStringSubmatch(text, -1) {
		if ids[match[1]] {
			t.Fatalf("rule id %s twice", match[1])
		}
		ids[match[1]] = true
	}
	if got := release.GreyChallengeProfiles(); len(got) != 1 || got[0] != strict.Ref.SHA256 {
		t.Fatalf("grey challenge profiles %v", got)
	}
	// the strict tier marks its challenging set; 标准防护 has none
	tier := DynamicWAFTier{RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 1 << 17, RequestBodyLimitAction: "reject",
		ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 1000}
	tier.Profile = strict.Ref
	strictTier, err := RenderDynamicWAFTier(release, tier)
	if err != nil || !strings.Contains(string(strictTier), "setvar:tx.cdnca_"+tx+"_grey=1") {
		t.Fatalf("strict tier %v: %s", err, strictTier)
	}
	tier.Profile = standard.Ref
	if standardTier, _ := RenderDynamicWAFTier(release, tier); strings.Contains(string(standardTier), "_grey=1") {
		t.Fatalf("standard tier challenges: %s", standardTier)
	}
	for _, absent := range []string{"cdnca_targets", "ruleRemoveTargetById", "CDNCA-TX-"} {
		if strings.Contains(text, absent) {
			t.Fatalf("node rules still carry %q", absent)
		}
	}
}

// An exclusion bucket (ADR 0011 RI-03d): its rule file
// includes its tier's and per site matches the context's site and removes
// each excluded target from its rule; sites sorted, 1 to 32; per site only
// exported rules, known locations, valid names, sorted and distinct, 1 to 32.
func TestDynamicWAFBucket(t *testing.T) {
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	release := dynamicTestRelease(t, standardTestProfile(testCRSProfileSHA256), strict)
	tier := DynamicWAFTier{Profile: strict.Ref, RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 1 << 17, RequestBodyLimitAction: "reject",
		ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 1000}
	exported := strict.Exports
	if len(exported) < 2 {
		t.Fatal("test profile exports too few rules")
	}
	rule, other := exported[0], exported[1]
	const second = "2d110000-0000-4000-8000-0000000000ff"
	targets := []DynamicWAFTarget{{rule, "args", "json.q"}, {rule, "args", "q"}, {rule, "cookie", "session"}, {other, "header", "X-A"}}
	sites := []DynamicWAFBucketSite{{managedWAFTestSiteID, targets}, {second, targets[1:2]}}
	content, err := RenderDynamicWAFBucket(release, tier, "/run/waf/tiers/"+tier.Key()+".conf", sites)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("# cdnca managed WAF exclusion bucket: tier %s, 2 sites\nInclude /run/waf/tiers/%s.conf\n"+
		"SecRule UNIQUE_ID \"@beginsWith c3;s=%s;\" \"id:38000,phase:1,pass,nolog,t:none,"+
		"ctl:ruleRemoveTargetById=%d;ARGS:json.q,ctl:ruleRemoveTargetById=%d;ARGS:q,"+
		"ctl:ruleRemoveTargetById=%d;REQUEST_COOKIES:session,ctl:ruleRemoveTargetById=%d;REQUEST_HEADERS:X-A,skipAfter:CDNCA-XB\"\n"+
		"SecRule UNIQUE_ID \"@beginsWith c3;s=%s;\" \"id:38001,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=%d;ARGS:q,skipAfter:CDNCA-XB\"\n"+
		"SecMarker \"CDNCA-XB\"\n",
		tier.Key(), tier.Key(), managedWAFTestSiteID, rule, rule, rule, other, second, rule)
	if string(content) != want {
		t.Fatalf("bucket file\n%s\nwant\n%s", content, want)
	}
	if got := DynamicWAFBucketLocation(tier, 3); got != "@cdnca_waf_"+tier.Key()+"_x3" {
		t.Fatalf("bucket location %q", got)
	}
	many := make([]DynamicWAFTarget, DynamicWAFMaxTargets+1)
	for index := range many {
		many[index] = DynamicWAFTarget{rule, "args", fmt.Sprintf("p%05d", index)}
	}
	crowd := make([]DynamicWAFBucketSite, DynamicWAFBucketSites+1)
	for index := range crowd {
		crowd[index] = DynamicWAFBucketSite{fmt.Sprintf("0d110000-0000-4000-8000-%012x", index), targets[:1]}
	}
	one := func(targets []DynamicWAFTarget) []DynamicWAFBucketSite {
		return []DynamicWAFBucketSite{{managedWAFTestSiteID, targets}}
	}
	for name, bad := range map[string][]DynamicWAFBucketSite{
		"no sites": {}, "too many sites": crowd, "site id": {{"0D110000-0000-4000-8000-00000000000A", targets[:1]}},
		"sites unsorted": {sites[1], sites[0]}, "site twice": {sites[0], sites[0]},
		"none": one(nil), "location": one([]DynamicWAFTarget{{rule, "query", "q"}}), "not exported": one([]DynamicWAFTarget{{800000, "args", "q"}}),
		"name": one([]DynamicWAFTarget{{rule, "args", "a b"}}), "twice": one([]DynamicWAFTarget{{rule, "args", "q"}, {rule, "args", "q"}}),
		"unsorted": one([]DynamicWAFTarget{{other, "args", "q"}, {rule, "args", "q"}}), "too many": one(many),
	} {
		if _, err := RenderDynamicWAFBucket(release, tier, "/run/waf/tiers/x.conf", bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := RenderDynamicWAFBucket(release, tier, "relative.conf", sites[:1]); err == nil {
		t.Error("relative tier file accepted")
	}
	if len(crowd[:DynamicWAFBucketSites]) != 128 {
		t.Fatal("bucket size")
	}
	if _, err := RenderDynamicWAFBucket(release, tier, "/run/waf/tiers/x.conf", crowd[:DynamicWAFBucketSites]); err != nil {
		t.Fatalf("full bucket: %v", err)
	}
}

// The WAF API a listener needs: a managed WAF needs the c3 context (v3).
func TestListenerSecurityWAFAPIVersion(t *testing.T) {
	if got := ListenerSecurityWAFAPIVersion(nil); got != 0 {
		t.Fatalf("nil %d", got)
	}
	if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{ManagedWAF: &ManagedWAF{}}); got != WAFAdaptiveAPIVersion {
		t.Fatalf("managed WAF %d", got)
	}
	if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{{}}}); got != 1 {
		t.Fatalf("policies %d", got)
	}
}

// A site holds at least 256 automatic
// exclusions in force; its bucket rule (one SecRule with every
// ctl:ruleRemoveTargetById) renders at that bound, one more is refused.
func TestDynamicWAFBucketCapacity(t *testing.T) {
	if DynamicWAFMaxTargets < 256 {
		t.Fatalf("DynamicWAFMaxTargets %d, want at least 256", DynamicWAFMaxTargets)
	}
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	release := dynamicTestRelease(t, standardTestProfile(testCRSProfileSHA256), strict)
	tier := DynamicWAFTier{Profile: strict.Ref, RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 1 << 17, RequestBodyLimitAction: "reject",
		ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 1000}
	full := make([]DynamicWAFTarget, DynamicWAFMaxTargets+1)
	for index := range full {
		full[index] = DynamicWAFTarget{strict.Exports[0], "args", fmt.Sprintf("%s%05d", strings.Repeat("p", 59), index)}
	}
	site := func(targets []DynamicWAFTarget) []DynamicWAFBucketSite {
		return []DynamicWAFBucketSite{{managedWAFTestSiteID, targets}}
	}
	content, err := RenderDynamicWAFBucket(release, tier, "/run/waf/tiers/x.conf", site(full[:DynamicWAFMaxTargets]))
	if err != nil {
		t.Fatalf("site at the bound: %v", err)
	}
	if got := strings.Count(string(content), "ctl:ruleRemoveTargetById="); got != DynamicWAFMaxTargets {
		t.Fatalf("%d targets rendered", got)
	}
	if _, err := RenderDynamicWAFBucket(release, tier, "/run/waf/tiers/x.conf", site(full)); err == nil {
		t.Fatal("one over the bound accepted")
	}
}

// waf-gap6 S2 (研究 §3.9): a source with DynamicWAFRepeatThreshold grey
// zone transactions on the site in a window carries d=repeat; the node
// rules then score every two-level set's weak sum as strong (as k= does
// for a tightened set), before the decisions. The grey zone rule (31000 +
// position*8 + 3) logs, so the transaction keeps its message and Lua reads
// it from $modsecurity_rule_ids (ModSecurity-nginx patch 01) in log.
func TestDynamicWAFRepeatSignal(t *testing.T) {
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	release := dynamicTestRelease(t, standardTestProfile(testCRSProfileSHA256), strict)
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	tx := managedSetTX(strict.Sets[0].Key)
	short := strings.TrimPrefix(strict.Sets[0].Key, "waf_set:")
	match := regexp.MustCompile(`SecRule TX:cdnca_tighten "@contains ,` + regexp.QuoteMeta(short) + `," "id:([0-9]+),`).FindStringSubmatch(text)
	if match == nil {
		t.Fatal("no tighten rule of the strict set")
	}
	base, _ := strconv.Atoi(match[1])
	position := (base - dynamicWAFAdaptID) / 8
	for _, want := range []string{
		fmt.Sprintf("SecRule TX:cdnca_detect \"@contains ,%s,\" \"id:%d,phase:2,pass,nolog,t:none,chain\"\n", DynamicWAFRepeat, dynamicWAFRepeatID+position),
		fmt.Sprintf("  SecRule TX:cdnca_%[1]s_weak_threshold \"@gt 0\" \"t:none,setvar:'tx.cdnca_%[1]s_score=+%%{tx.cdnca_%[1]s_weak}',setvar:tx.cdnca_%[1]s_weak=0\"\n", tx),
		fmt.Sprintf("SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"id:%d,phase:2,pass,log,t:none,msg:'cdnca waf grey %s',chain\"\n", tx, base+3, strict.Sets[0].Key),
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node rules lack %q", want)
		}
	}
	// after the shape and tighten rules, before the decisions
	repeat, tighten, decide := strings.Index(text, "@contains ,repeat,"), strings.Index(text, "SecRule TX:cdnca_tighten"), strings.Index(text, "\"id:30100,phase:2,deny")
	if repeat < tighten || decide < repeat {
		t.Fatalf("order tighten %d repeat %d decide %d", tighten, repeat, decide)
	}
	// d=repeat parses (after shape), the node patterns accept it
	context := testDynamicWAFContext()
	context.Detectors = append(context.Detectors, DynamicWAFRepeat)
	parsed, ok := ParseDynamicWAFContext(context.String())
	if !ok || !reflect.DeepEqual(parsed, context) || !nodeContextRules()[0].MatchString(context.String()) {
		t.Fatalf("repeat context %q refused", context.String())
	}
	before := testDynamicWAFContext()
	before.Detectors = []string{"sqli", DynamicWAFRepeat, DynamicWAFShape}
	if _, ok := ParseDynamicWAFContext(before.String()); ok {
		t.Fatal("repeat before shape accepted")
	}
	// Lua counts a grey zone transaction by these IDs (31000 + position*8 + 3)
	if (base+3-dynamicWAFAdaptID)%8 != 3 || base+3 >= dynamicWAFChallengeID {
		t.Fatalf("grey rule %d", base+3)
	}
}

// waf-gap10: an upgraded source (k= tightened set, d=repeat) scores its
// weak sum as strong at no less than the set's strong threshold, so a
// grey zone hit of a rule with a learned weight below it (941380: 4 < 5)
// blocks once upgraded: weak = max(weak, threshold) right before each
// weak-to-strong rule. Not upgraded, the weak sum keeps its learned weight.
func TestDynamicWAFUpgradeScoresAtStrongThreshold(t *testing.T) {
	strict := twoLevelTestProfile(strings.Repeat("d", 64))
	release := dynamicTestRelease(t, standardTestProfile(testCRSProfileSHA256), strict)
	rules, err := RenderDynamicWAFRules(release, "/var/log/cdnca/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	tx := managedSetTX(strict.Sets[0].Key)
	short := strings.TrimPrefix(strict.Sets[0].Key, "waf_set:")
	match := regexp.MustCompile(`SecRule TX:cdnca_tighten "@contains ,` + regexp.QuoteMeta(short) + `," "id:([0-9]+),`).FindStringSubmatch(text)
	if match == nil {
		t.Fatal("no tighten rule of the strict set")
	}
	base, _ := strconv.Atoi(match[1])
	position := (base - dynamicWAFAdaptID) / 8
	clamp := func(id int, variable, item string) string {
		return fmt.Sprintf("SecRule TX:cdnca_%[1]s_weak \"@gt 0\" \"id:%[2]d,phase:2,pass,nolog,t:none,chain\"\n"+
			"  SecRule TX:%[3]s \"@contains ,%[4]s,\" \"t:none,chain\"\n"+
			"  SecRule TX:cdnca_%[1]s_weak \"@lt %%{tx.cdnca_%[1]s_threshold}\" \"t:none,setvar:'tx.cdnca_%[1]s_weak=%%{tx.cdnca_%[1]s_threshold}'\"\n",
			tx, id, variable, item)
	}
	add := fmt.Sprintf("setvar:'tx.cdnca_%[1]s_score=+%%{tx.cdnca_%[1]s_weak}',setvar:tx.cdnca_%[1]s_weak=0", tx)
	for _, upgrade := range []struct{ clamp, add string }{
		{clamp(dynamicWAFUpgradeID+position*2, "cdnca_tighten", short),
			fmt.Sprintf("SecRule TX:cdnca_tighten \"@contains ,%s,\" \"id:%d,", short, base)},
		{clamp(dynamicWAFUpgradeID+position*2+1, "cdnca_detect", DynamicWAFRepeat),
			fmt.Sprintf("SecRule TX:cdnca_detect \"@contains ,%s,\" \"id:%d,", DynamicWAFRepeat, dynamicWAFRepeatID+position)},
	} {
		at := strings.Index(text, upgrade.clamp)
		to := strings.Index(text, upgrade.add)
		// the clamp right before its upgrade
		if at < 0 || to != at+len(upgrade.clamp) || !strings.HasPrefix(text[to:], upgrade.add) ||
			!strings.Contains(strings.SplitN(text[to:], "\nSecRule", 2)[0], add) {
			t.Fatalf("clamp %q at %d, upgrade %q at %d", upgrade.clamp, at, upgrade.add, to)
		}
	}
	// the clamp ranges stay clear of the next range for every set position
	if dynamicWAFUpgradeID < dynamicWAFRepeatID+dynamicWAFMaxSetKeys || dynamicWAFUpgradeID+dynamicWAFMaxSetKeys*2 > dynamicWAFBucketID {
		t.Fatalf("upgrade range %d", dynamicWAFUpgradeID)
	}
}
