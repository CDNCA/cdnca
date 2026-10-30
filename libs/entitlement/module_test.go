package entitlement

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestModuleFeatureCodeRoundTrip(t *testing.T) {
	cases := []struct {
		kind ModuleKind
		id   string
		code string
	}{
		{ModuleKindModule, "aggregated_edge", "module.aggregated_edge"},
		{ModuleKindPack, "ipintel.base", "pack.ipintel.base"},
		{ModuleKindTheme, "aurora", "theme.aurora"},
	}
	for _, tc := range cases {
		code, err := ModuleFeatureCode(tc.kind, tc.id)
		if err != nil || code != tc.code {
			t.Fatalf("ModuleFeatureCode(%s,%s) = %q,%v", tc.kind, tc.id, code, err)
		}
		kind, id, ok := ParseModuleFeatureCode(tc.code)
		if !ok || kind != tc.kind || id != tc.id {
			t.Fatalf("ParseModuleFeatureCode(%s) = %s,%s,%v", tc.code, kind, id, ok)
		}
	}
	for _, code := range []string{"sites.manage", "market.participate", "modules.x"} {
		if _, _, ok := ParseModuleFeatureCode(code); ok {
			t.Fatalf("ParseModuleFeatureCode(%s) accepted a non-module code", code)
		}
	}
}

func TestModuleFeatureCodeRejectsMalformedIDs(t *testing.T) {
	for _, id := range []string{"", ".x", "x.", "a..b", "A", "a b", "-x", strings.Repeat("a", 90)} {
		if _, err := ModuleFeatureCode(ModuleKindModule, id); !errors.Is(err, ErrInvalidModuleCode) {
			t.Fatalf("ModuleFeatureCode(module,%q) error = %v", id, err)
		}
	}
	if _, err := ModuleFeatureCode(ModuleKind("plugin"), "x"); !errors.Is(err, ErrInvalidModuleCode) {
		t.Fatalf("unknown kind accepted: %v", err)
	}
}

// A lease must not carry a reserved-prefix code without a valid module id; the
// same check guards both the issuer (ValidatePolicy) and the verifier.
func TestValidatePolicyRejectsMalformedModuleCodes(t *testing.T) {
	version := VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"}
	for _, code := range []string{"module.", "pack..x", "theme.x.", "module.a..b"} {
		if err := ValidatePolicy(version, []Feature{{Code: code}}, nil); !errors.Is(err, ErrInvalidLease) {
			t.Fatalf("ValidatePolicy(%q) error = %v", code, err)
		}
	}
	ok := []Feature{{Code: "module.aggregated_edge"}, {Code: "pack.crs"}, {Code: "sites.manage"}, {Code: "theme.aurora"}}
	if err := ValidatePolicy(version, ok, nil); err != nil {
		t.Fatalf("ValidatePolicy(valid module codes) error = %v", err)
	}
}

func TestLeaseModuleCodesFiltersAndKeepsOrder(t *testing.T) {
	lease := Lease{Features: []Feature{
		{Code: "certificates.issue"}, {Code: "module.aggregated_edge"}, {Code: "pack.crs"},
		{Code: "sites.manage"}, {Code: "theme.aurora"},
	}}
	got := lease.ModuleCodes()
	want := []string{"module.aggregated_edge", "pack.crs", "theme.aurora"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ModuleCodes() = %v, want %v", got, want)
	}
}

// Every catalog entry must declare what revocation does to existing state
// (ADR 0007 §3: 停新增 + 存量保持/摘除) and use a valid, unique code.
func TestModuleCatalogDeclaresRevokeBehavior(t *testing.T) {
	seen := map[string]bool{}
	catalog := ModuleCatalog()
	if len(catalog) == 0 {
		t.Fatal("ModuleCatalog() is empty")
	}
	for _, module := range catalog {
		if err := module.Validate(); err != nil {
			t.Fatalf("catalog entry %s invalid: %v", module.Code, err)
		}
		if seen[module.Code] {
			t.Fatalf("duplicate catalog code %s", module.Code)
		}
		seen[module.Code] = true
		if found, ok := LookupModule(module.Code); !ok || found.Code != module.Code {
			t.Fatalf("LookupModule(%s) = %v,%v", module.Code, found, ok)
		}
	}
	if !seen["module.aggregated_edge"] {
		t.Fatal("catalog lacks module.aggregated_edge (ADR 0008 §8)")
	}
	catalog[0].Code = "module.mutated"
	if _, ok := LookupModule("module.mutated"); ok {
		t.Fatal("ModuleCatalog() leaked its backing array")
	}
}

func TestModuleDescriptorValidate(t *testing.T) {
	valid := ModuleDescriptor{Code: "module.x", NameZH: "测试", NameEN: "Test", Revoke: RevokeKeepExisting}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}
	for name, mutate := range map[string]func(*ModuleDescriptor){
		"code":   func(d *ModuleDescriptor) { d.Code = "sites.manage" },
		"revoke": func(d *ModuleDescriptor) { d.Revoke = "" },
		"bogus":  func(d *ModuleDescriptor) { d.Revoke = "delete_everything" },
		"name":   func(d *ModuleDescriptor) { d.NameZH = "" },
	} {
		descriptor := valid
		mutate(&descriptor)
		if err := descriptor.Validate(); !errors.Is(err, ErrInvalidModuleCode) {
			t.Fatalf("Validate(%s) = %v", name, err)
		}
	}
}

// Official free modules (catalog Free flag) are what a new install's default
// plans carry; the set follows the catalog data, not a
// list kept elsewhere.
func TestFreeModuleCodesFollowCatalogFlag(t *testing.T) {
	catalog := []ModuleDescriptor{
		{Code: "pack.zeta", NameZH: "免费包", NameEN: "Free pack", Revoke: RevokeRemoveExisting, Free: true},
		{Code: "module.paid", NameZH: "付费", NameEN: "Paid", Revoke: RevokeKeepExisting},
		{Code: "module.alpha", NameZH: "免费", NameEN: "Free", Revoke: RevokeKeepExisting, Free: true},
	}
	if got := FreeModuleCodes(catalog); !reflect.DeepEqual(got, []string{"module.alpha", "pack.zeta"}) {
		t.Fatalf("FreeModuleCodes() = %v", got)
	}
	if got := FreeModuleCodes(nil); got == nil || len(got) != 0 {
		t.Fatalf("FreeModuleCodes(nil) = %#v, want empty", got)
	}
	for _, module := range ModuleCatalog() {
		if module.Free != slices.Contains(FreeModuleCodes(ModuleCatalog()), module.Code) {
			t.Fatalf("official catalog free set disagrees with %s", module.Code)
		}
	}
}

// ADR 0010 Q1/Q2: module.autodefense is official and free (new
// installs' default plans grant it); module.autodefense.auto is official and
// paid. Both declare the section 9.1 revoke semantics: stop new use, step
// existing mitigations down within 10 minutes, keep learned data 30 days.
func TestAutoDefenseModulesInCatalog(t *testing.T) {
	free := FreeModuleCodes(ModuleCatalog())
	for code, wantFree := range map[string]bool{ModuleAutoDefense: true, ModuleAutoDefenseAuto: false} {
		module, ok := LookupModule(code)
		if !ok || module.Kind() != ModuleKindModule || module.Free != wantFree || slices.Contains(free, code) != wantFree {
			t.Fatalf("%s = %+v, %v; want free=%v", code, module, ok, wantFree)
		}
		if module.Revoke != RevokeDrainExisting || module.DrainSeconds != 600 || module.RetainDays != 30 {
			t.Fatalf("%s revoke = %s/%d/%d", code, module.Revoke, module.DrainSeconds, module.RetainDays)
		}
	}
	catalog := ModuleCatalog()
	if !slices.IsSortedFunc(catalog, func(a, b ModuleDescriptor) int { return strings.Compare(a.Code, b.Code) }) {
		t.Fatal("ModuleCatalog() is not sorted by code")
	}
}

// Attack auto-escalation is an official free module: new
// installs' default plans grant it; revoking it drains like automatic defense.
func TestEscalateModuleInCatalog(t *testing.T) {
	module, ok := LookupModule(ModuleEscalate)
	if !ok || module.Kind() != ModuleKindModule || !module.Free || !slices.Contains(FreeModuleCodes(ModuleCatalog()), ModuleEscalate) {
		t.Fatalf("%s = %+v, %v; want official free module", ModuleEscalate, module, ok)
	}
	if module.NameZH != "攻击自动升级" || module.Validate() != nil ||
		module.Revoke != RevokeDrainExisting || module.DrainSeconds != 600 || module.RetainDays != 30 {
		t.Fatalf("%s descriptor = %+v", ModuleEscalate, module)
	}
}

func TestRevokeDrainExistingPhases(t *testing.T) {
	module, _ := LookupModule(ModuleAutoDefenseAuto)
	revokedAt := time.Date(2026, 10, 19, 4, 30, 0, 0, time.UTC)
	for elapsed, want := range map[time.Duration]RevokePhase{
		0: RevokePhaseDraining, 599 * time.Second: RevokePhaseDraining, 600 * time.Second: RevokePhaseRetained,
		30*24*time.Hour - time.Second: RevokePhaseRetained, 30 * 24 * time.Hour: RevokePhaseExpired,
	} {
		if got, ok := module.RevokePhaseAt(revokedAt, revokedAt.Add(elapsed)); !ok || got != want {
			t.Fatalf("phase after %s = %s,%v; want %s", elapsed, got, ok, want)
		}
	}
	keep, _ := LookupModule("module.icp")
	if phase, ok := keep.RevokePhaseAt(revokedAt, revokedAt); ok || phase != "" {
		t.Fatalf("keep_existing phase = %s,%v", phase, ok)
	}
}

func TestModuleDescriptorValidateDrain(t *testing.T) {
	valid := ModuleDescriptor{Code: "module.x", NameZH: "测试", NameEN: "Test", Revoke: RevokeDrainExisting,
		DrainSeconds: 600, RetainDays: 30}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(drain) = %v", err)
	}
	for name, mutate := range map[string]func(*ModuleDescriptor){
		"no drain":        func(d *ModuleDescriptor) { d.DrainSeconds = 0 },
		"no retain":       func(d *ModuleDescriptor) { d.RetainDays = 0 },
		"drain > retain":  func(d *ModuleDescriptor) { d.DrainSeconds, d.RetainDays = 2*24*3600, 1 },
		"keep with drain": func(d *ModuleDescriptor) { d.Revoke = RevokeKeepExisting },
	} {
		descriptor := valid
		mutate(&descriptor)
		if err := descriptor.Validate(); !errors.Is(err, ErrInvalidModuleCode) {
			t.Fatalf("Validate(%s) = %v", name, err)
		}
	}
}

// The billing system bridge (ADR 0019, Q1 a) is an official free module:
// new installs' default plans grant it; revoking it keeps what it opened.
func TestBillingBridgeModuleInCatalog(t *testing.T) {
	module, ok := LookupModule(ModuleBillingBridge)
	if !ok || module.Kind() != ModuleKindModule || !module.Free ||
		!slices.Contains(FreeModuleCodes(ModuleCatalog()), ModuleBillingBridge) {
		t.Fatalf("%s = %+v, %v; want official free module", ModuleBillingBridge, module, ok)
	}
	if module.NameZH != "财务系统对接" || module.Validate() != nil || module.Revoke != RevokeKeepExisting {
		t.Fatalf("%s descriptor = %+v", ModuleBillingBridge, module)
	}
}
