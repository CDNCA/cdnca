package securitybinding

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// ge-waf S3: a WAF policy's observe mode / auto block and its challenge /
// ban rules are stored with the policy and its version (migration 403) and
// carried by the published runtime snapshot.
func TestWAFSettingsAndActionsPersistAndPublish(t *testing.T) {
	fixture := newBindingFixture(t)
	pool, tenant := fixture.pool, fixture.tenantA
	sub := insertFeatureSubscription(t, pool, tenant.scopeID, tenant.userID, bindingTestNow, false, true)
	assignFeature(t, pool, tenant.scopeID, tenant.userID, sub, "waf", bindingTestNow)
	actor := tenantActor(tenant)
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, func() time.Time { return bindingTestNow }))
	path := func(value string) []securitypolicy.Condition {
		return []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{value}}}
	}
	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "waf actions", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow,
		WAFSettings: &securitypolicy.WAFSettings{Mode: securitypolicy.WAFModeObserve,
			AutoBlock: &securitypolicy.WAFAutoBlock{WindowSeconds: 60, HitThreshold: 20, BlockSeconds: 600}},
		Rules: []securitypolicy.Rule{
			{Name: "challenge login", Priority: 10, Enabled: true, Conditions: path("/login"), Action: securitypolicy.ActionChallenge,
				Flow: securitypolicy.FlowStop, ActionConfig: securitypolicy.ActionConfig{
					WAFChallenge: &securitypolicy.WAFChallengeAction{PassSeconds: 1800, PowBits: 12}}},
			{Name: "ban scanners", Priority: 20, Enabled: true, Conditions: path("/.git"), Action: securitypolicy.ActionBan,
				Flow: securitypolicy.FlowStop, ActionConfig: securitypolicy.ActionConfig{
					WAFBan: &securitypolicy.WAFBanConfig{BanSeconds: 3600}}},
		}}
	created, err := service.Create(t.Context(), actor, securitypolicy.CreateRequest{TargetScopeID: tenant.scopeID,
		OwnerUserID: tenant.userID, Fields: fields, IdempotencyKey: "waf-settings-create", RequestID: "waf-settings-create"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	stored, err := service.Get(t.Context(), actor, created.Policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	var document []byte
	if err := pool.QueryRow(t.Context(), `SELECT document FROM security_policy_versions WHERE policy_id=$1 AND revision=$2`,
		created.Policy.ID, created.Policy.Revision).Scan(&document); err != nil {
		t.Fatal(err)
	}
	var version securitypolicy.Policy
	if err := json.Unmarshal(document, &version); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(fields.WAFSettings)
	for name, settings := range map[string]*securitypolicy.WAFSettings{"created": created.Policy.WAFSettings,
		"row": stored.WAFSettings, "version": version.WAFSettings} {
		if got, _ := json.Marshal(settings); !bytes.Equal(got, want) {
			t.Fatalf("%s settings = %s, want %s", name, got, want)
		}
	}
	if stored.Rules[0].ActionConfig.WAFChallenge == nil || stored.Rules[1].ActionConfig.WAFBan.BanSeconds != 3600 {
		t.Fatalf("stored rules = %+v", stored.Rules)
	}
	runtime, err := securitypolicy.CompileRuntimeSnapshot(stored, tenant.siteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	if runtime.Snapshot.WAFSettings == nil || runtime.Snapshot.WAFSettings.Mode != securitypolicy.WAFModeObserve ||
		securitypolicy.ValidateRuntimeSnapshot(runtime.Snapshot) != nil {
		t.Fatalf("runtime snapshot = %s", runtime.CanonicalJSON)
	}
	linkFeatureSubscription(t, pool, tenant.siteID, sub)
	store := newBindingStore(t, pool, newRecordingSigner(), &testClock{now: bindingTestNow}, 5*time.Minute)
	publication, err := store.Publish(t.Context(), actor, PublishRequest{TenantScopeID: tenant.scopeID, SiteID: tenant.siteID,
		PolicyID: stored.ID, PolicyVersion: stored.Revision, TargetNodeIDs: []uuid.UUID{tenant.nodeID}, RolloutID: uuid.New(),
		IdempotencyKey: "waf-settings-publish", RequestID: "waf-settings-publish"})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if publication.RuntimeSnapshotSHA256 != runtime.SHA256 {
		t.Fatal("published runtime snapshot is not the policy's")
	}

	// A CC policy cannot carry WAF settings; the column CHECK backs the API.
	if _, err := pool.Exec(t.Context(), `UPDATE security_policies SET waf_settings='{}'::jsonb WHERE kind<>'waf'`); err == nil {
		t.Fatal("waf_settings accepted on a non-WAF policy")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE security_policies SET waf_settings='[]'::jsonb WHERE id=$1`, stored.ID); err == nil {
		t.Fatal("non-object waf_settings accepted")
	}
}

// ge-waf logic 1 / 2: the system default WAF draft reads the active platform
// defaults (a fresh installation: the project bootstrap, every module off,
// auto block off) and the synced catalog.
func TestCatalogDefaultWAFReadsPlatformDefaults(t *testing.T) {
	fixture := newBindingFixture(t)
	seedCatalog(t, fixture.pool)
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(fixture.pool, func() time.Time { return bindingTestNow }))
	result, err := service.CatalogRulesForScope(t.Context(), tenantActor(fixture.tenantA), fixture.tenantA.scopeID,
		securitypolicy.KindWAF, []string{securitypolicy.SystemDefaultWAFKey})
	if err != nil {
		t.Fatal(err)
	}
	if result.Default == nil || result.Default.Enabled || result.Default.WAFSettings != nil || len(result.Rules) != 0 {
		t.Fatalf("bootstrap default WAF = %+v", result.Default)
	}
}
