package dynwaf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// Fixtures: the signed catalog's CRS text and libs/rulepack's system CRS
// profile packs (what license migration 087 seeds).
func fixtures(t *testing.T) (*edgeconfig.CRSRuleText, map[string]edgeconfig.CRSProfile) {
	t.Helper()
	files, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]edgeconfig.CRSProfile{}
	paths, _ := filepath.Glob("../../../../libs/rulepack/testdata/crs-profiles/*.json")
	if len(paths) == 0 {
		t.Fatal("no CRS profile packs")
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		_, profile, err := rulepack.LoadCRSProfile(content, hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatal(err)
		}
		profiles[profile.Ref.SHA256] = profile
	}
	return &edgeconfig.CRSRuleText{Version: rulecatalog.CRSRulesBundle().Version, Files: files}, profiles
}

func profileNamed(t *testing.T, profiles map[string]edgeconfig.CRSProfile, pack string) edgeconfig.CRSProfile {
	t.Helper()
	for _, profile := range profiles {
		if profile.Ref.PackID == pack {
			return profile
		}
	}
	t.Fatalf("no %s", pack)
	return edgeconfig.CRSProfile{}
}

func site(id string, profile edgeconfig.CRSProfile, body int, exclusions ...int) edgesite.Site {
	if exclusions == nil {
		exclusions = []int{}
	}
	return edgesite.Site{SiteID: id, Security: edgesite.Security{ManagedWAF: &edgesite.ManagedWAF{
		PolicyID: "0d110000-0000-4000-8000-000000000001", PolicyVersion: 1,
		Profile: edgesite.ManagedWAFProfile{RequestBodyLimit: body, RequestBodyNoFilesLimit: 131072,
			RequestBodyLimitAction: "reject", ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000,
			InspectionLimitAction: "log"},
		CRSProfile: profile.Ref, Exclusions: exclusions, AllowCIDRs: []string{}}}}
}

func TestPrepareTiersAreSharedAndSiteFree(t *testing.T) {
	text, profiles := fixtures(t)
	pl1, pl2 := profileNamed(t, profiles, "system/crs-pl1"), profileNamed(t, profiles, "system/crs-pl2")
	root := t.TempDir()
	engine := &Engine{ModulePath: "/opt/waf/modules/ngx_http_modsecurity_module.so", UnicodeMapPath: "/opt/waf/unicode.mapping"}
	input := Input{CRSText: text, Profiles: profiles, Engine: engine, Root: root, AuditLog: "/var/lib/node/shared/modsecurity-audit.log",
		Sites: []edgesite.Site{
			site("0d110000-0000-4000-8000-00000000000a", pl1, 1<<20, 942100),
			site("0d110000-0000-4000-8000-00000000000b", pl1, 1<<20), // same tier as a
			site("0d110000-0000-4000-8000-00000000000c", pl2, 1<<20),
			site("0d110000-0000-4000-8000-00000000000d", pl1, 2<<20),
			{SiteID: "0d110000-0000-4000-8000-00000000000e"}, // no managed WAF
		}}
	result, err := Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skeleton.Tiers) != 3 {
		t.Fatalf("%d tiers, want 3", len(result.Skeleton.Tiers))
	}
	for key, path := range result.Skeleton.Tiers {
		content, err := os.ReadFile(path)
		if err != nil || !strings.HasPrefix(string(content), "# cdnca managed WAF tier "+key+":") {
			t.Fatalf("tier %s: %v", key, err)
		}
		// waf-cookie-fp2: only the two-level (pl2) tier has a cookie variant,
		// the tier without its weak rules' cookie target changes
		variantPath, has := result.Skeleton.CookieTiers[key]
		twoLevel := strings.Contains(string(content), "SecRuleUpdateTargetById")
		if has != twoLevel {
			t.Fatalf("tier %s: cookie variant %t, two-level %t", key, has, twoLevel)
		}
		if has {
			variant, err := os.ReadFile(variantPath)
			if err != nil || strings.Contains(string(variant), "SecRuleUpdateTargetById") || !strings.HasPrefix(string(content), string(variant)) {
				t.Fatalf("tier %s cookie variant: %v", key, err)
			}
		}
	}
	if len(result.Skeleton.CookieTiers) != 1 {
		t.Fatalf("%d cookie variants, want 1", len(result.Skeleton.CookieTiers))
	}
	rules, err := os.ReadFile(result.Skeleton.RulesPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range input.Sites {
		if strings.Contains(string(rules), site.SiteID) {
			t.Fatal("node rules name a site")
		}
	}
	if _, err := os.Stat(filepath.Join(result.Directory, "crs", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf")); err != nil {
		t.Fatal(err)
	}
	// A site edit inside the same tiers (other exclusions, a new site of an
	// existing tier) changes nothing on disk: same digest, no reload.
	input.Sites[0] = site("0d110000-0000-4000-8000-00000000000a", pl1, 1<<20, 941100, 942100)
	input.Sites = append(input.Sites, site("0d110000-0000-4000-8000-00000000000f", pl2, 1<<20))
	again, err := Prepare(input)
	if err != nil || again.Digest != result.Digest {
		t.Fatalf("site-only change moved the configuration: %v %s %s", err, again.Digest, result.Digest)
	}
	// a new tier is a new configuration
	input.Sites = append(input.Sites, site("0d110000-0000-4000-8000-000000000010", pl2, 4<<20))
	grown, err := Prepare(input)
	if err != nil || grown.Digest == result.Digest || len(grown.Skeleton.Tiers) != 4 {
		t.Fatalf("new tier: %v %d", err, len(grown.Skeleton.Tiers))
	}
	if err := Retain(root, grown.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(result.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old configuration kept")
	}
}

// Automatic exclusions (ADR 0011 RI-03d): the sites with
// some in force are grouped per tier into exclusion buckets of at most
// DynamicWAFBucketSites sites (one location each, whose file includes the
// tier's of the same configuration directory); other sites stay in their
// tier; a change of the exclusions is a new configuration (reload); there is
// no node-wide bound.
func TestPrepareSiteExclusions(t *testing.T) {
	text, profiles := fixtures(t)
	pl2 := profileNamed(t, profiles, "system/crs-pl2")
	hot, cold := "0d110000-0000-4000-8000-00000000000a", "0d110000-0000-4000-8000-00000000000b"
	input := Input{CRSText: text, Profiles: profiles, Root: t.TempDir(), AuditLog: "/var/lib/node/shared/modsecurity-audit.log",
		Engine: &Engine{ModulePath: "/opt/waf/modules/ngx_http_modsecurity_module.so", UnicodeMapPath: "/opt/waf/unicode.mapping"},
		Sites:  []edgesite.Site{site(hot, pl2, 1<<20), site(cold, pl2, 1<<20)}}
	plain, err := Prepare(input)
	if err != nil || len(plain.Skeleton.Buckets) != 0 || len(plain.Skeleton.SiteBuckets) != 0 {
		t.Fatalf("no exclusions: %v %v", err, plain.Skeleton.Buckets)
	}
	rule := pl2.Exports[0]
	input.Targets = map[string][]edgeconfig.DynamicWAFTarget{hot: {{Rule: rule, Location: "args", Name: "q"}}, cold: {}}
	result, err := Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	var tier edgeconfig.DynamicWAFTier
	for _, value := range result.Tiers {
		tier = value
	}
	bucket := edgeconfig.DynamicWAFBucketLocation(tier, 0)
	if len(result.Skeleton.Buckets) != 1 || len(result.Skeleton.SiteBuckets) != 1 || result.Skeleton.SiteBuckets[hot] != bucket ||
		result.Digest == plain.Digest {
		t.Fatalf("buckets %v sites %v, digest moved %v", result.Skeleton.Buckets, result.Skeleton.SiteBuckets, result.Digest != plain.Digest)
	}
	content, err := os.ReadFile(result.Skeleton.Buckets[bucket])
	if err != nil {
		t.Fatal(err)
	}
	tierFile := result.Skeleton.Tiers[tier.Key()]
	if !strings.Contains(string(content), "Include "+tierFile+"\n") ||
		!strings.Contains(string(content), fmt.Sprintf("SecRule UNIQUE_ID \"@beginsWith c3;s=%s;\" \"id:38000,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=%d;ARGS:q,skipAfter:CDNCA-XB\"\n", hot, rule)) ||
		strings.Contains(string(content), cold) || filepath.Dir(filepath.Dir(tierFile)) != result.Directory {
		t.Fatalf("bucket file %s (tier %s)", content, tierFile)
	}
	// ri-wire: the two-level tier's bucket has a cookie variant, the same
	// site rules over the tier's cookie variant
	variant, err := os.ReadFile(result.Skeleton.CookieBuckets[bucket])
	variantTier := result.Skeleton.CookieTiers[tier.Key()]
	if err != nil || len(result.Skeleton.CookieBuckets) != 1 || variantTier == "" ||
		string(variant) != strings.Replace(string(content), "Include "+tierFile+"\n", "Include "+variantTier+"\n", 1) {
		t.Fatalf("bucket cookie variant %q: %v\n%s", result.Skeleton.CookieBuckets, err, variant)
	}
	again, err := Prepare(input)
	if err != nil || again.Digest != result.Digest {
		t.Fatalf("same exclusions moved the configuration: %v", err)
	}
	input.Targets[hot] = append(input.Targets[hot], edgeconfig.DynamicWAFTarget{Rule: rule, Location: "args", Name: "r"})
	if changed, err := Prepare(input); err != nil || changed.Digest == result.Digest {
		t.Fatalf("new exclusion kept the configuration: %v", err)
	}
	input.Targets[hot] = []edgeconfig.DynamicWAFTarget{{Rule: 800000, Location: "args", Name: "q"}}
	if _, err := Prepare(input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unexported rule: %v", err)
	}
	// no node-wide bound: 1000 sites of two tiers (750 + 250) fill ceil(n/128) buckets
	// per tier, in site ID order
	input.Targets = map[string][]edgeconfig.DynamicWAFTarget{}
	input.Sites = nil
	for index := range 1000 {
		id := fmt.Sprintf("0d110000-0000-4000-8000-%012x", 0x100+index)
		limit := 1 << 20
		if index%4 == 0 {
			limit = 2 << 20
		}
		input.Sites = append(input.Sites, site(id, pl2, limit))
		input.Targets[id] = []edgeconfig.DynamicWAFTarget{{Rule: rule, Location: "args", Name: "q"}}
	}
	many, err := Prepare(input)
	if err != nil {
		t.Fatalf("1000 sites: %v", err)
	}
	if len(many.Skeleton.SiteBuckets) != 1000 || len(many.Skeleton.Buckets) != 6+2 {
		t.Fatalf("1000 sites: %d sites in %d buckets", len(many.Skeleton.SiteBuckets), len(many.Skeleton.Buckets))
	}
	first := input.Sites[1].SiteID // the first site of the 1 MiB tier
	if location := many.Skeleton.SiteBuckets[first]; !strings.HasSuffix(location, "_x0") ||
		many.Skeleton.SiteBuckets[input.Sites[0].SiteID] == location {
		t.Fatalf("first site's bucket %q", location)
	}
}

func TestPrepareRefusesWhatTheNodeCannotRun(t *testing.T) {
	text, profiles := fixtures(t)
	pl1 := profileNamed(t, profiles, "system/crs-pl1")
	engine := &Engine{ModulePath: "/opt/m.so", UnicodeMapPath: "/opt/u"}
	base := Input{CRSText: text, Profiles: profiles, Engine: engine, Root: t.TempDir(), AuditLog: "/a/audit.log"}
	if result, err := Prepare(base); err != nil || result.Skeleton != nil {
		t.Fatalf("no managed WAF site: %+v %v", result, err)
	}
	unknown := pl1
	unknown.Ref.SHA256 = strings.Repeat("0", 64)
	notExported := site("0d110000-0000-4000-8000-00000000000a", pl1, 1<<20, 920100)
	for name, mutate := range map[string]func(*Input){
		"no engine": func(in *Input) { in.Engine = nil },
		"unknown profile": func(in *Input) {
			in.Sites = []edgesite.Site{site("0d110000-0000-4000-8000-00000000000a", unknown, 1<<20)}
		},
		"not exported": func(in *Input) { in.Sites = []edgesite.Site{notExported} },
	} {
		input := base
		input.Sites = []edgesite.Site{site("0d110000-0000-4000-8000-00000000000a", pl1, 1<<20)}
		mutate(&input)
		if _, err := Prepare(input); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A site's application types are its own tier: the tier file carries the
// WordPress pack (parser rule IDs rewritten to the dynamic node rules), the
// same profile without apps is another tier, and a pack the node does not
// hold refuses the site.
func TestPrepareAppsAreTheirOwnTier(t *testing.T) {
	text, profiles := fixtures(t)
	pl1 := profileNamed(t, profiles, "system/crs-pl1")
	content, err := os.ReadFile("../../../../libs/rulepack/testdata/crs-apps/app-wordpress.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	_, wordpress, err := rulepack.LoadCRSApp(content, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	wp := site("0d110000-0000-4000-8000-00000000000a", pl1, 1<<20)
	wp.Security.ManagedWAF.Apps = []edgeconfig.CRSAppRef{wordpress.Ref}
	plain := site("0d110000-0000-4000-8000-00000000000b", pl1, 1<<20)
	input := Input{CRSText: text, Profiles: profiles, Engine: &Engine{ModulePath: "/m.so", UnicodeMapPath: "/u"},
		Root: t.TempDir(), AuditLog: "/var/lib/node/shared/modsecurity-audit.log", Sites: []edgesite.Site{wp, plain}}
	if _, err := Prepare(input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("app pack not on the node: %v", err)
	}
	input.Apps = map[string]edgeconfig.CRSApp{wordpress.Ref.SHA256: wordpress}
	result, err := Prepare(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skeleton.Tiers) != 2 {
		t.Fatalf("tiers %v", result.Skeleton.Tiers)
	}
	key := wp.Security.ManagedWAF.Edge().TierOf().Key()
	if !strings.HasSuffix(key, "_x"+wordpress.Ref.SHA256[:8]) {
		t.Fatalf("key %s", key)
	}
	tier, err := os.ReadFile(result.Skeleton.Tiers[key])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tier), "id:9507100,") || strings.Contains(string(tier), "ctl:ruleRemoveById=10001") ||
		!strings.Contains(string(tier), "ctl:ruleRemoveById=30009") {
		t.Fatalf("tier file lacks the rewritten WordPress pack")
	}
	plainTier, _ := os.ReadFile(result.Skeleton.Tiers[plain.Security.ManagedWAF.Edge().TierOf().Key()])
	main, _ := os.ReadFile(result.Skeleton.RulesPath)
	if strings.Contains(string(plainTier), "9507") || strings.Contains(string(main), "9507") {
		t.Fatal("WordPress text outside its tier")
	}
}
