package rulepack

import (
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// modSecurityPack is testdata system-crs.json renamed to a non-profile pack
// whose single rule is the crs_sqli set, changed by change.
func modSecurityPack(t *testing.T, change func(set map[string]any)) *CompiledPack {
	t.Helper()
	return mustCompileModified(t, "system-crs.json", func(document map[string]any) {
		document["pack_id"] = "system/sqli-narrow"
		rule := document["rules"].([]any)[0].(map[string]any)
		rule["id"] = "crs_sqli"
		if change != nil {
			change(rule["crs"].(map[string]any))
		}
	})
}

func narrowFixture(t *testing.T) (*edgeconfig.CRSManifest, edgeconfig.CRSProfile) {
	t.Helper()
	manifest, err := edgeconfig.DeriveCRSManifest(catalogCRSText(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range loadedCRSProfiles(t) {
		if profile.Ref.PackID == "system/crs-pl1" {
			return manifest, profile
		}
	}
	t.Fatal("no system/crs-pl1")
	return nil, edgeconfig.CRSProfile{}
}

func narrow(t *testing.T, pack *CompiledPack, site []int) ([]int, error) {
	t.Helper()
	manifest, profile := narrowFixture(t)
	resolution := Resolve([]MountRequest{{Pack: pack}}, Target{})
	if resolution.Security == nil {
		t.Fatalf("resolve: %+v", resolution.Conflicts)
	}
	rules, err := ModSecurityRules(resolution.Security.Mounts[0], pack)
	if err != nil {
		return nil, err
	}
	return NarrowCRSProfile(manifest, profile, site, rules)
}

func TestNarrowCRSProfileExcludesWhatThePackLeavesOut(t *testing.T) {
	manifest, profile := narrowFixture(t)
	pack := modSecurityPack(t, func(set map[string]any) { set["exclude_ids"] = []any{942100} })
	got, err := narrow(t, pack, []int{941100})
	if err != nil {
		t.Fatal(err)
	}
	// Every rule of the profile's other sets, the pack's own exclusion and
	// the site's exclusion; nothing else of crs_sqli.
	want := []int{941100, 942100}
	for _, set := range profile.Sets {
		if set.Key != "waf_set:crs_sqli" {
			want = append(want, crsTierSet(manifest, set).Rules...)
		}
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if !slices.Equal(got, want) {
		t.Fatalf("exclusions = %v, want %v", got, want)
	}
	if _, kept := slices.BinarySearch(got, 942140); kept {
		t.Fatal("942140 (a crs_sqli rule the pack runs) excluded")
	}
}

func TestNarrowCRSProfileRefusesWhatTheProfileDoesNotRun(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"higher paranoia":      func(set map[string]any) { set["paranoia"] = 2 },
		"other action":         func(set map[string]any) { set["action"] = "log" },
		"other threshold":      func(set map[string]any) { set["threshold"] = 10 },
		"rules of another set": func(set map[string]any) { set["files"] = []any{"REQUEST-942", "REQUEST-941"} },
		"rule of another set":  func(set map[string]any) { set["include_ids"] = []any{941100} },
	} {
		if _, err := narrow(t, modSecurityPack(t, change), nil); !errors.Is(err, ErrOutOfProfile) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	unknownSet := mustCompileModified(t, "system-crs.json", func(document map[string]any) {
		document["pack_id"] = "system/sqli-narrow"
		document["rules"].([]any)[0].(map[string]any)["id"] = "crs_java"
	})
	if _, err := narrow(t, unknownSet, nil); !errors.Is(err, ErrOutOfProfile) {
		t.Fatalf("set outside the profile: %v", err)
	}
	if _, err := NarrowCRSProfile(nil, edgeconfig.CRSProfile{}, nil, nil); !errors.Is(err, ErrOutOfProfile) {
		t.Fatalf("no rule text: %v", err)
	}
}

func TestSiteCRSExclusions(t *testing.T) {
	manifest, profile := narrowFixture(t)
	pack := modSecurityPack(t, nil)
	waf := wafPack(t, "system/block-a", "block", "/a")
	resolution := Resolve([]MountRequest{{Pack: pack}, {Pack: waf}}, Target{})
	if resolution.Security == nil {
		t.Fatalf("resolve: %+v", resolution.Conflicts)
	}
	packs := map[string]*CompiledPack{pack.SHA256: pack, waf.SHA256: waf}
	got, ok, err := SiteCRSExclusions(resolution.Security.Mounts, packs, manifest, &profile, []int{942100})
	if err != nil || !ok || len(got) == 0 || slices.Contains(got, 942140) || !slices.Contains(got, 942100) {
		t.Fatalf("exclusions %v ok %v: %v", got, ok, err)
	}
	if _, ok, err := SiteCRSExclusions(resolution.Security.Mounts, packs, manifest, nil, nil); !ok || !errors.Is(err, ErrOutOfProfile) {
		t.Fatalf("no managed WAF: ok %v %v", ok, err)
	}
	requests := []MountRequest{{Pack: pack, Source: Source{DisableAt: []LevelRef{{Level: LevelSite}}}}, {Pack: waf}}
	if checked := CheckCRSProfile(Resolve(requests, Target{}), requests, manifest, &profile, nil); checked.Security == nil {
		t.Fatalf("in profile refused: %+v", checked.Conflicts)
	}
	refused := CheckCRSProfile(Resolve(requests, Target{}), requests, manifest, nil, nil)
	if refused.Security != nil || len(refused.Conflicts) != 1 || refused.Conflicts[0].Code != ConflictCRSOutOfProfile ||
		len(refused.Conflicts[0].Sides) != 1 || refused.Conflicts[0].Sides[0].PackID != "system/sqli-narrow" ||
		len(refused.Conflicts[0].Remedies) != 1 || refused.Conflicts[0].Remedies[0].Action != "disable_pack" {
		t.Fatalf("refused = %+v", refused)
	}
	only := Resolve([]MountRequest{{Pack: waf}}, Target{})
	same, ok, err := SiteCRSExclusions(only.Security.Mounts, packs, manifest, nil, []int{942100})
	if err != nil || ok || !slices.Equal(same, []int{942100}) {
		t.Fatalf("without modsecurity: %v %v %v", same, ok, err)
	}
}
