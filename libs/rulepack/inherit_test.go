package rulepack

import "testing"

const siteA1 = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1"
const siteA2 = "a2a2a2a2-a2a2-4a2a-8a2a-a2a2a2a2a2a2"

func effectOf(t *testing.T, effects []Effect, packID string) Effect {
	t.Helper()
	for _, effect := range effects {
		if effect.Pack.Pack.PackID == packID {
			return effect
		}
	}
	t.Fatalf("pack %s not visible", packID)
	return Effect{}
}

func TestDownloadedPackIsNotEnabled(t *testing.T) {
	pack := wafPack(t, "system/x", "block", "/x")
	effects := Effective([]*CompiledPack{pack}, nil, Subject{TenantScopeID: tenantA, SiteID: siteA1})
	if effect := effectOf(t, effects, "system/x"); effect.Enabled || effect.EnabledAt.Level != LevelDefault {
		t.Fatalf("effect = %+v", effect)
	}
	if len(MountRequests(effects)) != 0 {
		t.Fatal("a downloaded, never enabled pack became a mount")
	}
}

// Platform enables (allowing tenants), tenant A disables (allowing sites),
// site A1 enables again: only site A1 runs the pack.
func TestThreeStateInheritance(t *testing.T) {
	pack := wafPack(t, "system/x", "block", "/x")
	priority := 100
	overrides := []Override{
		{Level: LevelPlatform, PackID: "system/x", State: StateEnabled, AllowLower: true},
		{Level: LevelTenant, ObjectID: tenantA, PackID: "system/x", State: StateDisabled, AllowLower: true},
		{Level: LevelSite, ObjectID: siteA1, PackID: "system/x", State: StateEnabled, Priority: &priority},
	}
	packs := []*CompiledPack{pack}
	cases := []struct {
		subject Subject
		enabled bool
		at      Level
	}{
		{Subject{}, true, LevelPlatform},
		{Subject{TenantScopeID: tenantA}, false, LevelTenant},
		{Subject{TenantScopeID: tenantA, SiteID: siteA1}, true, LevelSite},
		{Subject{TenantScopeID: tenantA, SiteID: siteA2}, false, LevelTenant},
		{Subject{TenantScopeID: tenantB, SiteID: siteA2}, true, LevelPlatform},
	}
	for _, item := range cases {
		effect := effectOf(t, Effective(packs, overrides, item.subject), "system/x")
		if effect.Enabled != item.enabled || effect.EnabledAt.Level != item.at {
			t.Errorf("%+v: enabled=%v at=%s", item.subject, effect.Enabled, effect.EnabledAt.Level)
		}
	}
	// What each subject's own "inherit" would follow: the levels above it.
	for subject, inherited := range map[Subject]bool{
		{}: false, {TenantScopeID: tenantA}: true, {TenantScopeID: tenantA, SiteID: siteA1}: false,
	} {
		if effect := effectOf(t, Effective(packs, overrides, subject), "system/x"); effect.Inherited != inherited {
			t.Errorf("%+v: inherited=%v", subject, effect.Inherited)
		}
	}
	site := effectOf(t, Effective(packs, overrides, Subject{TenantScopeID: tenantA, SiteID: siteA1}), "system/x")
	if site.Priority != 100 || len(site.Adjustable) != 3 {
		t.Fatalf("site effect = %+v", site)
	}
}

func TestLockedLevelsAreIgnored(t *testing.T) {
	pack := wafPack(t, "system/x", "block", "/x")
	packs := []*CompiledPack{pack}
	// No platform row: a system pack is locked to the platform; a tenant row
	// is ignored.
	overrides := []Override{{Level: LevelTenant, ObjectID: tenantA, PackID: "system/x", State: StateEnabled}}
	effect := effectOf(t, Effective(packs, overrides, Subject{TenantScopeID: tenantA}), "system/x")
	if effect.Enabled || len(effect.Ignored) != 1 || len(effect.Adjustable) != 1 {
		t.Fatalf("locked: %+v", effect)
	}
	// Platform enabled without allow_lower: the tenant cannot switch it off.
	overrides = []Override{
		{Level: LevelPlatform, PackID: "system/x", State: StateEnabled},
		{Level: LevelTenant, ObjectID: tenantA, PackID: "system/x", State: StateDisabled},
		{Level: LevelSite, ObjectID: siteA1, PackID: "system/x", RuleID: "r1", State: StateDisabled},
	}
	effect = effectOf(t, Effective(packs, overrides, Subject{TenantScopeID: tenantA, SiteID: siteA1}), "system/x")
	if !effect.Enabled || len(effect.Ignored) != 2 || len(effect.RuleStates) != 0 {
		t.Fatalf("platform lock: %+v", effect)
	}
	// Rule level with adjustment allowed.
	overrides[0].AllowLower, overrides[1].AllowLower = true, true
	overrides[1].State = StateInherit
	effect = effectOf(t, Effective(packs, overrides, Subject{TenantScopeID: tenantA, SiteID: siteA1}), "system/x")
	if !effect.Enabled || effect.RuleStates["r1"] || effect.RuleSource["r1"].Level != LevelSite {
		t.Fatalf("rule level: %+v", effect)
	}
}

func TestUserPacksBelongToTheirTenant(t *testing.T) {
	own := wafPack(t, "user/"+tenantA+"/allow", "allow", "/a")
	overrides := []Override{{Level: LevelSite, ObjectID: siteA1, PackID: own.Pack.PackID, State: StateEnabled}}
	if effects := Effective([]*CompiledPack{own}, overrides, Subject{TenantScopeID: tenantB, SiteID: siteA1}); len(effects) != 0 {
		t.Fatal("another tenant sees the user pack")
	}
	if effects := Effective([]*CompiledPack{own}, overrides, Subject{}); len(effects) != 0 {
		t.Fatal("the platform view lists a tenant's user pack")
	}
	// The owner tenant may adjust it without any platform row.
	effect := effectOf(t, Effective([]*CompiledPack{own}, overrides, Subject{TenantScopeID: tenantA, SiteID: siteA1}), own.Pack.PackID)
	if !effect.Enabled || effect.EnabledAt.Level != LevelSite {
		t.Fatalf("own user pack: %+v", effect)
	}
	requests := MountRequests([]Effect{effect})
	if len(requests) != 1 || requests[0].Source.EnabledAt.ObjectID != siteA1 {
		t.Fatalf("requests = %+v", requests)
	}
}
