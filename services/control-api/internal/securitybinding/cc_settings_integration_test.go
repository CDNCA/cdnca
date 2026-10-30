package securitybinding

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedCatalog writes the current system rule catalog as a signed delivery
// would (security_rule_catalog_apply).
func seedCatalog(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT set_config('cdnca.security_rule_catalog_apply','on',true)`); err != nil {
			return err
		}
		delivery := uuid.New()
		for _, item := range rulecatalog.CurrentSeed() {
			body, err := json.Marshal(item.Body)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO security_system_rules(system_key,kind,legacy_id,name,description,sort,hidden,
				revision,body,status,delivery_id,first_seen_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,now(),now())
				ON CONFLICT (system_key) DO NOTHING`, item.SystemKey, item.Kind, item.LegacyID, item.Name, item.Description,
				item.Sort, item.Hidden, item.Revision, body, delivery); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func setGlobalCC(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, document string) {
	t.Helper()
	digest := sha256.Sum256([]byte(document))
	if _, err := pool.Exec(t.Context(), `INSERT INTO openresty_security_configs(id,tenant_scope_id,scope_type,scope_id,document,
		document_sha256,revision,created_at,updated_at) VALUES($1,$2,'global','0',$3,$4,1,now(),now())
		ON CONFLICT (tenant_scope_id,scope_type,scope_id) WHERE deleted_at IS NULL
		DO UPDATE SET document=EXCLUDED.document,document_sha256=EXCLUDED.document_sha256,revision=openresty_security_configs.revision+1`,
		uuid.New(), scopeID, document, digest[:]); err != nil {
		t.Fatal(err)
	}
}

func ccRuleForTest(name string, requests int) securitypolicy.Rule {
	return securitypolicy.Rule{Name: name, Priority: 10, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
		Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
			WindowSeconds: 5, MaxRequests: requests, ResponseAction: "temporary_ban", BanSeconds: 360}}}
}

// TestCCSettingsPersistResolveAndPublish: a CC policy's site settings are
// stored with the policy and its version, system-mode values follow the
// tenant's global CC config (blacklist time; the global auto switch expands
// its catalog rule group), auto switch rule IDs stay stable across saves,
// and the published runtime snapshot carries the durations and the switch.
func TestCCSettingsPersistResolveAndPublish(t *testing.T) {
	fixture := newBindingFixture(t)
	pool, tenant := fixture.pool, fixture.tenantA
	seedCatalog(t, pool)
	setGlobalCC(t, pool, tenant.scopeID, `{"block_time":7200,"white_time":43200,"auto_switch":{"enable":true,"qps_50x":30,"qps_total":500,"rule":"10003","seconds":0}}`)
	sub := insertFeatureSubscription(t, pool, tenant.scopeID, tenant.userID, bindingTestNow, false, false)
	assignFeature(t, pool, tenant.scopeID, tenant.userID, sub, "custom_cc", bindingTestNow)
	actor := tenantActor(tenant)
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, func() time.Time { return bindingTestNow }))

	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindCC, Name: "site cc", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{ccRuleForTest("relaxed", 300)},
		CCSettings: &securitypolicy.CCSettings{
			BanSeconds:  &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingSystem},
			PassSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: 3600},
			AutoSwitch:  &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingSystem, RuleGroups: []string{}, Rules: []securitypolicy.Rule{}},
		}}
	created, err := service.Create(t.Context(), actor, securitypolicy.CreateRequest{TargetScopeID: tenant.scopeID,
		OwnerUserID: tenant.userID, Fields: fields, IdempotencyKey: "cc-settings-create", RequestID: "cc-settings-create"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	settings := created.Policy.CCSettings
	if settings == nil || settings.BanSeconds.Seconds != 7200 || settings.PassSeconds.Seconds != 3600 {
		t.Fatalf("durations = %+v", settings)
	}
	value := settings.AutoSwitch
	if value.Mode != securitypolicy.CCSettingSystem || value.QPSTotal != 500 || value.QPS5xx != 30 ||
		value.RecoverSeconds != securitypolicy.CCAutoSwitchDefaultRecoverSeconds ||
		len(value.RuleGroups) != 1 || value.RuleGroups[0] != "cc_rule:10003" || len(value.Rules) != 1 ||
		value.Rules[0].ID == uuid.Nil || value.Rules[0].Action != securitypolicy.ActionChallenge ||
		value.Rules[0].ActionConfig.Challenge.Type != "rotate_image" {
		t.Fatalf("system auto switch = %+v", value)
	}
	switchRuleID := value.Rules[0].ID

	// Read back from the row and from the version document.
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
	storedJSON, _ := json.Marshal(stored.CCSettings)
	versionJSON, _ := json.Marshal(version.CCSettings)
	createdJSON, _ := json.Marshal(created.Policy.CCSettings)
	if !bytes.Equal(storedJSON, createdJSON) || !bytes.Equal(versionJSON, createdJSON) {
		t.Fatalf("stored settings differ:\nrow %s\nversion %s\ncreated %s", storedJSON, versionJSON, createdJSON)
	}

	// Saving again keeps the switch rule's ID; the published snapshot runs
	// the site durations and carries the switch.
	update := securitypolicy.UpdateRequest{ID: created.Policy.ID, ExpectedRevision: created.Policy.Revision,
		Fields: securitypolicy.PolicyFields{Kind: securitypolicy.KindCC, Name: "site cc", Enabled: true,
			DefaultAction: securitypolicy.ActionAllow, Rules: stored.Rules, CCSettings: stored.CCSettings},
		IdempotencyKey: "cc-settings-update", RequestID: "cc-settings-update"}
	updated, err := service.Update(t.Context(), actor, update)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Policy.CCSettings.AutoSwitch.Rules[0].ID != switchRuleID {
		t.Fatalf("switch rule ID changed %s -> %s", switchRuleID, updated.Policy.CCSettings.AutoSwitch.Rules[0].ID)
	}
	runtime, err := securitypolicy.CompileRuntimeSnapshot(updated.Policy, tenant.siteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	if runtime.Snapshot.Rules[0].ActionConfig.RateLimit.BanSeconds != 7200 || runtime.Snapshot.AutoSwitch == nil ||
		runtime.Snapshot.AutoSwitch.QPSTotal != 500 || runtime.Snapshot.AutoSwitch.Rules[0].ActionConfig.Challenge.PassSeconds != 3600 {
		t.Fatalf("runtime snapshot = %s", runtime.CanonicalJSON)
	}
	linkFeatureSubscription(t, pool, tenant.siteID, sub)
	store := newBindingStore(t, pool, newRecordingSigner(), &testClock{now: bindingTestNow}, 5*time.Minute)
	request := PublishRequest{TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, PolicyID: updated.Policy.ID,
		PolicyVersion: updated.Policy.Revision, TargetNodeIDs: []uuid.UUID{tenant.nodeID}, RolloutID: uuid.New(),
		IdempotencyKey: "cc-settings-publish", RequestID: "cc-settings-publish"}
	publication, err := store.Publish(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if publication.RuntimeSnapshotSHA256 != runtime.SHA256 {
		t.Fatal("published runtime snapshot is not the policy's")
	}

	// A disabled global auto switch resolves the site's system switch off;
	// custom thresholds without rules are refused.
	setGlobalCC(t, pool, tenant.scopeID, `{"block_time":0,"auto_switch":{"enable":false,"qps_50x":0,"qps_total":0,"rule":"","seconds":0}}`)
	update.ExpectedRevision, update.IdempotencyKey = updated.Policy.Revision, "cc-settings-off"
	update.Fields.CCSettings = &securitypolicy.CCSettings{BanSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingSystem},
		AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingSystem, RuleGroups: []string{}, Rules: []securitypolicy.Rule{}}}
	off, err := service.Update(t.Context(), actor, update)
	if err != nil {
		t.Fatalf("Update off: %v", err)
	}
	if off.Policy.CCSettings.AutoSwitch.Active() || off.Policy.CCSettings.BanSeconds.Seconds != 3600 {
		t.Fatalf("global off / block_time 0 resolved to %+v", off.Policy.CCSettings)
	}
	update.ExpectedRevision, update.IdempotencyKey = off.Policy.Revision, "cc-settings-bad"
	update.Fields.CCSettings = &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom,
		QPSTotal: 100, RecoverSeconds: 300, RuleGroups: []string{}, Rules: []securitypolicy.Rule{}}}
	if _, err := service.Update(t.Context(), actor, update); !errors.Is(err, securitypolicy.ErrInvalidInput) {
		t.Fatalf("custom switch without rules: %v", err)
	}
	// Custom: new rules get derived IDs.
	update.Fields.CCSettings.AutoSwitch.Rules = []securitypolicy.Rule{ccRuleForTest("strict", 20)}
	custom, err := service.Update(t.Context(), actor, update)
	if err != nil {
		t.Fatalf("custom switch: %v", err)
	}
	if rule := custom.Policy.CCSettings.AutoSwitch.Rules[0]; rule.ID == uuid.Nil || rule.ActionConfig.RateLimit.MaxRequests != 20 {
		t.Fatalf("custom switch rules = %+v", custom.Policy.CCSettings.AutoSwitch.Rules)
	}
}
