package edgeconfig

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func dynamicTestRelease(t *testing.T, profiles ...CRSProfile) *DynamicWAFRelease {
	t.Helper()
	if len(profiles) == 0 {
		profiles = []CRSProfile{testCRSProfile(testCRSProfileSHA256)}
	}
	release, err := ResolveDynamicWAFRelease(testCRSRuleText(), profiles)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

// secondTestProfile scores the same sets with other paranoia/actions (one
// membership per set key across a node's profiles).
func secondTestProfile(digest string) CRSProfile {
	profile := testCRSProfile(digest)
	profile.Ref.PackID = "system/crs-test2"
	profile.Sets[0].Paranoia, profile.Sets[0].Threshold = 1, 3
	profile.Sets[1].Action, profile.Sets[1].Paranoia = "block", 2
	manifest, _ := DeriveCRSManifest(testCRSRuleText())
	profile.Exports = nil
	for _, rule := range manifest.Rules {
		if strings.HasPrefix(rule.File, "REQUEST-942-") && rule.Paranoia <= 1 || strings.HasPrefix(rule.File, "REQUEST-941-") && rule.Paranoia <= 2 {
			profile.Exports = append(profile.Exports, rule.ID)
		}
	}
	return profile
}

// The tier file is v7's per-site file (renderManagedWAFSite) without the
// site: the same limits, TX values and removed rules; the allow CIDRs, the
// inspection-limit mode and the exclusions come per request (context).
func TestDynamicWAFTierMatchesV7SiteFile(t *testing.T) {
	site := managedWAFTestSite()
	site.ManagedWAF.AllowCIDRs = nil
	normalized, err := normalizeManagedWAF(site.ManagedWAF)
	if err != nil {
		t.Fatal(err)
	}
	site.ManagedWAF = normalized
	v7, err := resolveManagedWAFRelease([]Site{site}, testCRSRuleText(), []CRSProfile{testCRSProfile(testCRSProfileSHA256)}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := renderManagedWAFSite(v7, site)
	got, err := RenderDynamicWAFTier(dynamicTestRelease(t), normalized.TierOf())
	if err != nil {
		t.Fatal(err)
	}
	strip := func(text []byte) string {
		lines := strings.Split(string(text), "\n")
		kept := lines[:0]
		for _, line := range lines {
			if strings.HasPrefix(line, "#") {
				continue
			}
			// rule IDs differ by range (v7 20000+, tiers 39000)
			line = regexp.MustCompile(`id:[0-9]+,`).ReplaceAllString(line, "id:N,")
			kept = append(kept, strings.Replace(line, "setvar:tx.cdnca_inspection_limit_mode=log,", "", 1))
		}
		return strings.Join(kept, "\n")
	}
	if strip(got) != strip(want) {
		t.Fatalf("tier file differs from v7's site file\n--- tier\n%s\n--- v7\n%s", got, want)
	}
}

func TestDynamicWAFTierKeyIsStableAndDistinct(t *testing.T) {
	tier := managedWAFTestSite().ManagedWAF.TierOf()
	if got, want := tier.Key(), "aaaaaaaaaaaaaaaa_b1048576_n131072_r_a1000_j512_p100000"; got != want {
		t.Fatalf("key %q, want %q", got, want)
	}
	seen := map[string]bool{tier.Key(): true}
	for name, change := range map[string]func(*DynamicWAFTier){
		"profile": func(t *DynamicWAFTier) { t.Profile.SHA256 = strings.Repeat("b", 64) },
		"body":    func(t *DynamicWAFTier) { t.RequestBodyLimit++ },
		"nofiles": func(t *DynamicWAFTier) { t.RequestBodyNoFilesLimit++ },
		"action":  func(t *DynamicWAFTier) { t.RequestBodyLimitAction = "partial" },
		"args":    func(t *DynamicWAFTier) { t.ArgumentsLimit++ },
		"json":    func(t *DynamicWAFTier) { t.JSONDepthLimit++ },
		"pcre":    func(t *DynamicWAFTier) { t.PCREMatchLimit++ },
	} {
		changed := tier
		change(&changed)
		if seen[changed.Key()] {
			t.Fatalf("%s: key %q not distinct", name, changed.Key())
		}
		seen[changed.Key()] = true
	}
	if !regexp.MustCompile(`^@cdnca_waf_[0-9a-z_]+$`).MatchString(tier.Location()) {
		t.Fatalf("location %q", tier.Location())
	}
}

func TestDynamicWAFRulesDependOnNoSite(t *testing.T) {
	release := dynamicTestRelease(t, testCRSProfile(testCRSProfileSHA256), secondTestProfile(strings.Repeat("b", 64)))
	rules, err := RenderDynamicWAFRules(release, "/runtime/shared/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	for _, forbidden := range []string{managedWAFTestSiteID, "SecRequestBodyLimit", "REQUEST_HEADERS:X-", "ctl:ruleEngine=DetectionOnly"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("node rules contain %q", forbidden)
		}
	}
	for _, want := range []string{
		`SecRule UNIQUE_ID "@rx ^c3;s=`, `SecRule &TX:cdnca_exclude "@eq 0" "id:30002,phase:1,deny,status:500`,
		`SecRule TX:cdnca_engine "@streq 0" "id:30003,phase:1,pass,nolog,t:none,ctl:ruleEngine=Off"`, "SecAuditEngine Off\n",
		`skipAfter:CDNCA-EX-9421`, `SecRule TX:cdnca_exclude "@contains ,942100," `, `ctl:ruleRemoveById=942100"`,
		"Include crs/REQUEST-901-INITIALIZATION.conf", "Include crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node rules lack %q", want)
		}
	}
	// one exclusion hook per exported rule of the union of the profiles
	if got, want := strings.Count(text, `"@contains ,9`), len(release.Exports()); got != want {
		t.Fatalf("%d exclusion hooks, want %d", got, want)
	}
	again, _ := RenderDynamicWAFRules(release, "/runtime/shared/modsecurity-audit.log")
	if string(again) != text {
		t.Fatal("rendering is not deterministic")
	}
	ids := map[string]bool{}
	for _, match := range regexp.MustCompile(`"id:([0-9]+),`).FindAllStringSubmatch(text, -1) {
		if ids[match[1]] {
			t.Fatalf("rule id %s twice", match[1])
		}
		ids[match[1]] = true
	}
}

func testDynamicWAFContext() DynamicWAFContext {
	return DynamicWAFContext{SiteID: managedWAFTestSiteID, InspectionBlock: true, GreyPassed: true, Browser: true, IntelBonus: 20,
		Detectors: []string{"sqli", "ssti", DynamicWAFShape}, GreyFloor: 6, Tighten: []string{"crs_sqli", "crs_xss"},
		TuningOff: []int{7, 12}, Exclusions: []int{941100, 942100}, RequestID: "0123456789abcdef0123456789abcdef"}
}

// nodeContextRules are DynamicWAFContextRules for Go's RE2 (it caps a
// repeat count at 1000; PCRE takes the bounds as written).
func nodeContextRules() [2]*regexp.Regexp {
	widen := regexp.MustCompile(`\{0,[0-9]{4}\}`)
	return [2]*regexp.Regexp{regexp.MustCompile(widen.ReplaceAllString(DynamicWAFContextRules[0], "*")),
		regexp.MustCompile(widen.ReplaceAllString(DynamicWAFContextRules[1], "*"))}
}

func TestDynamicWAFContextRoundTripAndPattern(t *testing.T) {
	context := testDynamicWAFContext()
	text := context.String()
	want := "c3;s=" + managedWAFTestSiteID + ";i=b;e=1;g=1;b=1;p=20;d=,sqli,ssti,shape,;f=6;k=,crs_sqli,crs_xss,;" +
		"u=,7,12,;x=,941100,942100,;|0123456789abcdef0123456789abcdef"
	if text != want {
		t.Fatalf("context %q, want %q", text, want)
	}
	parsed, ok := ParseDynamicWAFContext(text)
	if !ok || !reflect.DeepEqual(parsed, context) {
		t.Fatalf("parsed %+v %v", parsed, ok)
	}
	none := DynamicWAFContext{SiteID: managedWAFTestSiteID, EngineOff: true, RequestID: "a"}
	if got := none.String(); got != "c3;s="+managedWAFTestSiteID+";i=l;e=0;g=0;b=0;p=0;d=,;f=0;k=,;u=,;x=,;|a" {
		t.Fatalf("empty context %q", got)
	}
	if parsed, ok := ParseDynamicWAFContext(none.String()); !ok || !parsed.EngineOff || parsed.GreyFloor != 0 || parsed.Tighten == nil {
		t.Fatalf("empty context parsed %+v %v", parsed, ok)
	}
	rules := nodeContextRules()
	for _, good := range []string{text, none.String()} {
		head := rules[0].FindStringSubmatch(good)
		tail := rules[1].FindStringSubmatch(good)
		if head == nil || tail == nil || len(head) != 9 || len(tail) != 4 || head[1] != managedWAFTestSiteID {
			t.Fatalf("node rule patterns refuse %q", good)
		}
	}
	if head := rules[0].FindStringSubmatch(text); head[4] != "1" || head[5] != "1" || head[6] != "20" || head[7] != ",sqli,ssti,shape," || head[8] != "6" {
		t.Fatalf("head captures %q", head)
	}
	if tail := rules[1].FindStringSubmatch(text); tail[1] != ",crs_sqli,crs_xss," || tail[2] != ",7,12," || tail[3] != ",941100,942100," {
		t.Fatalf("tail captures %q", tail)
	}
	for name, bad := range map[string]string{
		"empty":            "",
		"c2":               strings.Replace(text, "c3;", "c2;", 1),
		"site":             strings.Replace(text, managedWAFTestSiteID, "x", 1),
		"no g":             strings.Replace(text, ";g=1", "", 1),
		"g=2":              strings.Replace(text, ";g=1", ";g=2", 1),
		"p=101":            strings.Replace(text, ";p=20", ";p=101", 1),
		"p=07":             strings.Replace(text, ";p=20", ";p=07", 1),
		"no f":             strings.Replace(text, ";f=6", "", 1),
		"f=100":            strings.Replace(text, ";f=6", ";f=100", 1),
		"f=06":             strings.Replace(text, ";f=6", ";f=06", 1),
		"t= segment":       strings.Replace(text, ";u=", ";t=,942100:a:q,;u=", 1),
		"unknown signal":   strings.Replace(text, ",sqli,", ",sqlx,", 1),
		"signal order":     strings.Replace(text, ",sqli,ssti,", ",ssti,sqli,", 1),
		"signal twice":     strings.Replace(text, ",sqli,ssti,", ",sqli,sqli,", 1),
		"upper signal":     strings.Replace(text, ",sqli,", ",SQLI,", 1),
		"tighten order":    strings.Replace(text, ",crs_sqli,crs_xss,", ",crs_xss,crs_sqli,", 1),
		"tighten prefix":   strings.Replace(text, ",crs_sqli,", ",waf_set:crs_sqli,", 1),
		"tuning zero":      strings.Replace(text, ",7,12,", ",0,12,", 1),
		"tuning order":     strings.Replace(text, ",7,12,", ",12,7,", 1),
		"exclusion digits": strings.Replace(text, ",941100,", ",94110,", 1),
		"exclusion order":  strings.Replace(text, ",941100,942100,", ",942100,941100,", 1),
		"segment order":    strings.Replace(text, ";u=,7,12,;x=,941100,942100,", ";x=,941100,942100,;u=,7,12,", 1),
		"no comma":         strings.Replace(text, ";u=,7,12,", ";u=7,12", 1),
		"trailing":         text + "|",
		"leading":          "X" + text,
		"request id":       strings.Replace(text, "|0123", "|01-3", 1),
	} {
		if _, ok := ParseDynamicWAFContext(bad); ok {
			t.Fatalf("%s accepted: %q", name, bad)
		}
	}
}

// TestDynamicWAFContextBounds: every segment at its item bound with the
// longest items parses and the node rule patterns accept it, and together
// they fit DynamicWAFContextMax (nothing is ever dropped); one item more is
// refused.
func TestDynamicWAFContextBounds(t *testing.T) {
	name := strings.Repeat("n", 64)
	if !WAFParamNamePattern.MatchString(name) || WAFParamNamePattern.MatchString(name+"n") {
		t.Fatal("parameter names are 1-64 bytes")
	}
	full := DynamicWAFContext{SiteID: managedWAFTestSiteID, IntelBonus: DynamicWAFMaxIntelBonus, RequestID: strings.Repeat("f", 64)}
	for _, detector := range DynamicWAFDetectors {
		full.Detectors = append(full.Detectors, detector.Name)
	}
	full.Detectors = append(full.Detectors, DynamicWAFShape)
	for index := 0; index < DynamicWAFMaxTighten; index++ {
		full.Tighten = append(full.Tighten, strings.Repeat("s", 31)+string(rune('a'+index)))
	}
	full.GreyFloor = DynamicWAFMaxGreyFloor
	for index := 0; index < DynamicWAFMaxTuningOff; index++ {
		full.TuningOff = append(full.TuningOff, 100000+index)
	}
	segments := map[string]int{}
	text := full.String()
	for _, part := range strings.Split(text, ";") {
		key, value, _ := strings.Cut(part, "=")
		segments[key] = len(value)
	}
	if segments["d"] > dynamicWAFDetectBytes || segments["k"] > dynamicWAFTightenBytes || segments["u"] > dynamicWAFTuningOffBytes {
		t.Fatalf("a segment at its item bound exceeds its byte bound: %v", segments)
	}
	// every list at its item bound (x= at its byte bound) fits
	for index := 0; index < MaxManagedWAFExclusions; index++ {
		full.Exclusions = append(full.Exclusions, 920000+index)
	}
	text = full.String()
	if len(text) > DynamicWAFContextMax {
		t.Fatalf("full context %d bytes", len(text))
	}
	parsed, ok := ParseDynamicWAFContext(text)
	if !ok || !reflect.DeepEqual(parsed, full) {
		t.Fatalf("full context refused (%d bytes)", len(text))
	}
	rules := nodeContextRules()
	if !rules[0].MatchString(text) || !rules[1].MatchString(text) {
		t.Fatal("node rule patterns refuse the full context")
	}
	over := full
	over.GreyFloor = DynamicWAFMaxGreyFloor + 1
	if _, ok := ParseDynamicWAFContext(over.String()); ok {
		t.Fatal("grey floor 100 accepted")
	}
	over = full
	over.Tighten = append(append([]string(nil), full.Tighten...), "zz")
	if _, ok := ParseDynamicWAFContext(over.String()); ok {
		t.Fatal("11 tightened sets accepted")
	}
	over = full
	over.TuningOff = append(append([]int(nil), full.TuningOff...), 999999)
	if _, ok := ParseDynamicWAFContext(over.String()); ok {
		t.Fatal("65 tuning entries accepted")
	}
	over = full
	over.Exclusions = append(append([]int(nil), full.Exclusions...), 999999)
	if _, ok := ParseDynamicWAFContext(over.String()); ok {
		t.Fatal("257 exclusions accepted")
	}
}

// FuzzParseDynamicWAFContext: whatever parses is within the bounds, writes
// back to the same bytes and is accepted by the node rule patterns.
func FuzzParseDynamicWAFContext(f *testing.F) {
	f.Add(testDynamicWAFContext().String())
	f.Add(DynamicWAFContext{SiteID: managedWAFTestSiteID, RequestID: "a"}.String())
	f.Add("c3;s=" + managedWAFTestSiteID + ";i=l;e=1;g=0;b=0;p=100;d=,cmd,;f=9;k=,;u=,1,;x=,;|z")
	rules := nodeContextRules()
	f.Fuzz(func(t *testing.T, value string) {
		context, ok := ParseDynamicWAFContext(value)
		if !ok {
			return
		}
		if context.String() != value || len(value) > DynamicWAFContextMax || context.GreyFloor > DynamicWAFMaxGreyFloor ||
			len(context.Tighten) > DynamicWAFMaxTighten || len(context.TuningOff) > DynamicWAFMaxTuningOff ||
			len(context.Exclusions) > MaxManagedWAFExclusions || context.IntelBonus > DynamicWAFMaxIntelBonus {
			t.Fatalf("parsed %q to %+v", value, context)
		}
		if !rules[0].MatchString(value) || !rules[1].MatchString(value) {
			t.Fatalf("node rule patterns refuse %q", value)
		}
	})
}

func TestDynamicWAFReleaseChecksProfilesAndSites(t *testing.T) {
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no profile: %v", err)
	}
	// same digest prefix: the tier keys would collide
	a, b := testCRSProfile(strings.Repeat("c", 64)), secondTestProfile(strings.Repeat("c", 63)+"d")
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{a, b}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("colliding tags: %v", err)
	}
	conflicting := secondTestProfile(strings.Repeat("b", 64))
	conflicting.Sets[0].Files = []string{"REQUEST-942", "REQUEST-941"}
	conflicting.Sets = conflicting.Sets[:1]
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{testCRSProfile(testCRSProfileSHA256), conflicting}); err == nil {
		t.Fatal("conflicting set membership accepted")
	}
	release := dynamicTestRelease(t)
	site := *managedWAFTestSite().ManagedWAF
	if err := release.CheckSite(site); err != nil {
		t.Fatal(err)
	}
	unknown := site
	unknown.Profile.SHA256 = strings.Repeat("e", 64)
	if release.CheckSite(unknown) == nil {
		t.Fatal("unknown profile accepted")
	}
	notExported := site
	notExported.Exclusions = []int{920100}
	if release.CheckSite(notExported) == nil {
		t.Fatal("unexported exclusion accepted")
	}
	if _, err := RenderDynamicWAFTier(release, unknown.TierOf()); err == nil {
		t.Fatal("tier of an unknown profile rendered")
	}
}
