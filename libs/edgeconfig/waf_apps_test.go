package edgeconfig

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const testAppSHA256 = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"

func testCRSApp() CRSApp {
	return CRSApp{Ref: CRSAppRef{PackID: "system/app-wordpress", Version: "1.2.0", SHA256: testAppSHA256},
		Key: "wordpress", Name: "WordPress", FirstID: 9507000, LastID: 9507999,
		Before: "SecRule REQUEST_FILENAME \"@endsWith /wp-login.php\" \"id:9507100,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942430;ARGS:redirect_to\"\n" +
			"SecRule REQUEST_FILENAME \"!@contains /wp-admin/\" \"id:9507400,phase:1,pass,nolog,skipAfter:END-WORDPRESS-ADMIN\"\n" +
			"SecMarker \"END-WORDPRESS-ADMIN\"\n",
		Markers: []string{"END-WORDPRESS-ADMIN"}}
}

func appSite(apps ...CRSAppRef) Site {
	site := managedWAFTestSite()
	waf := *site.ManagedWAF
	waf.Apps = apps
	site.ManagedWAF = &waf
	return site
}

func TestManagedWAFAppsAreGatedPerSite(t *testing.T) {
	app := testCRSApp()
	wordpress := appSite(app.Ref)
	plain := appSite()
	plain.ID = "44444444-4444-4444-8444-444444444444"
	for _, site := range []*Site{&wordpress, &plain} {
		normalized, err := normalizeManagedWAF(site.ManagedWAF)
		if err != nil {
			t.Fatal(err)
		}
		site.ManagedWAF = normalized
	}
	release, err := resolveManagedWAFRelease([]Site{wordpress, plain}, testCRSRuleText(),
		[]CRSProfile{testCRSProfile(testCRSProfileSHA256)}, false, app)
	if err != nil {
		t.Fatal(err)
	}
	main, err := renderManagedWAFMain(release, "/runtime")
	if err != nil {
		t.Fatal(err)
	}
	text := string(main)
	// The app text is node-wide, behind one guard per phase, before CRS.
	for phase := 1; phase <= 4; phase++ {
		guard := "SecRule UNIQUE_ID \"!@contains |awordpress|\" \"id:" + itoa(12000+phase-1) + ",phase:" + itoa(phase) +
			",pass,nolog,t:none,skipAfter:CDNCA-APP-WORDPRESS\""
		if !strings.Contains(text, guard) {
			t.Fatalf("phase %d guard missing:\n%s", phase, text)
		}
	}
	appAt, crsAt := strings.Index(text, "id:9507100"), strings.Index(text, "REQUEST-901-INITIALIZATION.conf")
	if appAt < 0 || crsAt < 0 || appAt > crsAt || !strings.Contains(text, "SecMarker \"CDNCA-APP-WORDPRESS\"") {
		t.Fatalf("app text not before CRS initialisation:\n%s", text)
	}
	// Only the site that selected it marks its transactions.
	gate, err := RenderWAFEngineGate(mustManifest(t, release), WAFEngineGate{ReleasePath: "/r", ModulePath: "/m.so", UnicodeMapPath: "/u"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(gate["site-"+wordpress.ID+".conf"]); !strings.Contains(got, "|awordpress|") {
		t.Fatalf("wordpress site gate: %s", got)
	}
	if got := string(gate["site-"+plain.ID+".conf"]); strings.Contains(got, "|a") {
		t.Fatalf("plain site gate marks an app: %s", got)
	}
}

func TestManagedWAFAppsMustBeCarried(t *testing.T) {
	app := testCRSApp()
	site := appSite(app.Ref)
	profiles := []CRSProfile{testCRSProfile(testCRSProfileSHA256)}
	if _, err := resolveManagedWAFRelease([]Site{site}, testCRSRuleText(), profiles, false); err == nil {
		t.Fatal("a site's app pack the release does not carry was accepted")
	}
	other := app
	other.Ref.Version = "1.3.0"
	if _, err := resolveManagedWAFRelease([]Site{site}, testCRSRuleText(), profiles, false, other); err == nil {
		t.Fatal("an app pack of another version was accepted")
	}
	clash := app
	clash.Markers = []string{"CDNCA-EX-9421"}
	if _, err := resolveManagedWAFRelease([]Site{site}, testCRSRuleText(), profiles, false, clash); err == nil {
		t.Fatal("an app marker in the node namespace was accepted")
	}
	unsorted := appSite(CRSAppRef{PackID: "system/app-xenforo", Version: "1.0.0", SHA256: strings.Repeat("c", 64)}, app.Ref)
	if _, err := normalizeManagedWAF(unsorted.ManagedWAF); err == nil {
		t.Fatal("unsorted application types were accepted")
	}
}

// Dynamic routing runs a site's application types in its tier location:
// the tier key names the apps, the tier file carries their text after the
// profile values (the tier's rules precede the node rules, so the apps run
// before CRS initialises, as on site runtime 8), and the node rule IDs the
// plugins remove (v8 numbering) are rewritten to the dynamic node rules.
func TestDynamicWAFRunsAppsInTier(t *testing.T) {
	app := testCRSApp()
	app.Before += "SecRule REQUEST_FILENAME \"@endsWith /wp-json\" \"id:9507200,phase:1,pass,nolog,ctl:ruleRemoveById=10001,ctl:ruleRemoveById=10005\"\n"
	waf := *appSite(app.Ref).ManagedWAF
	waf.AllowCIDRs = nil
	if err := dynamicTestRelease(t).CheckSite(waf); err == nil {
		t.Fatal("a site's app pack the release does not carry was accepted")
	}
	release, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{testCRSProfile(testCRSProfileSHA256)}, app)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.CheckSite(waf); err != nil {
		t.Fatal(err)
	}
	other := waf
	other.Apps = []CRSAppRef{{PackID: app.Ref.PackID, Version: "9.9.9", SHA256: strings.Repeat("c", 64)}}
	if release.CheckSite(other) == nil {
		t.Fatal("an app version the release does not carry was accepted")
	}
	normalized, err := normalizeManagedWAF(&waf)
	if err != nil {
		t.Fatal(err)
	}
	tier, plain := normalized.TierOf(), (*managedWAFTestSite().ManagedWAF).TierOf()
	if want := plain.Key() + "_x" + testAppSHA256[:8]; tier.Key() != want {
		t.Fatalf("key %q, want %q", tier.Key(), want)
	}
	file, err := RenderDynamicWAFTier(release, tier)
	if err != nil {
		t.Fatal(err)
	}
	text := string(file)
	profileAt, appAt := strings.Index(text, "id:39000,"), strings.Index(text, "id:9507100,")
	if profileAt < 0 || appAt < profileAt || !strings.Contains(text, "SecMarker \"END-WORDPRESS-ADMIN\"") {
		t.Fatalf("app text not after the profile values:\n%s", text)
	}
	if strings.Contains(text, "UNIQUE_ID") || strings.Contains(text, "=10001") ||
		!strings.Contains(text, "ctl:ruleRemoveById=30009,ctl:ruleRemoveById=30011") {
		t.Fatalf("app text not ungated or parser rule IDs not rewritten:\n%s", text)
	}
	without, err := RenderDynamicWAFTier(release, plain)
	if err != nil || strings.Contains(string(without), "9507100") {
		t.Fatalf("tier without apps carries app text: %v\n%s", err, without)
	}
	// the rewritten IDs are the dynamic node rules' parser rules
	rules, err := RenderDynamicWAFRules(release, "/runtime/shared/modsecurity-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	for v8, dynamic := range map[int]string{
		10001: "REQBODY_ERROR", 10003: "&ARGS", 10004: "MULTIPART_STRICT_ERROR", 10005: "MULTIPART_UNMATCHED_BOUNDARY",
	} {
		id := dynamicWAFParserRuleIDs[v8]
		if !strings.Contains(string(rules), "SecRule "+dynamic+" ") || !strings.Contains(string(rules), dynamic+" \"") ||
			!regexp.MustCompile(`SecRule `+regexp.QuoteMeta(dynamic)+` "[^"]*" "id:`+itoa(id)+`,`).Match(rules) {
			t.Fatalf("v8 rule %d maps to %d, which is not the node's %s rule", v8, id, dynamic)
		}
	}
	// app packs must be distinct per key and marker, outside the node namespace
	clash := app
	clash.Markers = []string{"CDNCA-EX-9421"}
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{testCRSProfile(testCRSProfileSHA256)}, clash); err == nil {
		t.Fatal("an app marker in the node namespace was accepted")
	}
	twice := app
	twice.Ref.Version, twice.Ref.SHA256 = "1.3.0", strings.Repeat("d", 64)
	if _, err := ResolveDynamicWAFRelease(testCRSRuleText(), []CRSProfile{testCRSProfile(testCRSProfileSHA256)}, app, twice); err == nil {
		t.Fatal("two versions of one application were accepted")
	}
}

func mustManifest(t *testing.T, release *managedWAFRelease) WAFEngineManifest {
	t.Helper()
	manifest, err := ParseWAFEngineManifest(renderWAFEngineManifest(release))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func itoa(value int) string { return strconv.Itoa(value) }
