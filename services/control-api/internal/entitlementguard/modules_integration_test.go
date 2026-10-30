package entitlementguard

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
)

const testModule = "module.pa15_probe"

func (fixture webhookFeatureFixture) moduleLease(serial uint64, modules ...string) entitlement.Lease {
	lease := integrationLease(fixture.now, serial)
	features := []entitlement.Feature{{Code: FeatureExtensionsWebhooks}}
	for _, code := range modules {
		features = append(features, entitlement.Feature{Code: code})
	}
	sortFeatures(features)
	lease.Features = features
	lease.Quotas = []entitlement.Quota{{Code: QuotaExtensionsWebhooksCount, Limit: 3}}
	return lease
}

func sortFeatures(features []entitlement.Feature) {
	for i := 1; i < len(features); i++ {
		for j := i; j > 0 && features[j].Code < features[j-1].Code; j-- {
			features[j], features[j-1] = features[j-1], features[j]
		}
	}
}

func (fixture webhookFeatureFixture) grantedModules(t *testing.T) ModuleGrants {
	t.Helper()
	tx := fixture.begin(t)
	defer tx.Rollback(t.Context())
	grants, err := fixture.guard().GrantedModules(t.Context(), tx)
	if err != nil {
		t.Fatalf("GrantedModules() error = %v", err)
	}
	return grants
}

func (fixture webhookFeatureFixture) checkModule(t *testing.T, code, suffix string) error {
	t.Helper()
	tx := fixture.begin(t)
	defer tx.Rollback(t.Context())
	_, err := fixture.guard().CheckModule(t.Context(), tx, ModuleCheck{
		TargetScopeID: fixture.targetScope, ActorScopeID: fixture.actorScope, ActorUserID: fixture.actorUser,
		ResourceType: "module_probe", ResourceID: fixture.resourceID, RequestID: "module-" + suffix,
		Operation: "module_probe.use", Module: code,
	})
	return err
}

type moduleAuditRow struct {
	action  string
	result  string
	payload map[string]any
	changes []audit.Change // the changes column
}

func (fixture webhookFeatureFixture) moduleAudits(t *testing.T) []moduleAuditRow {
	t.Helper()
	rows, err := fixture.pool.Query(t.Context(), `SELECT action,result,payload,changes FROM audit_events
		WHERE action=$1 ORDER BY occurred_at,stream_position`, ModulesChangedAction)
	if err != nil {
		t.Fatalf("query module audits: %v", err)
	}
	defer rows.Close()
	var result []moduleAuditRow
	for rows.Next() {
		var row moduleAuditRow
		var payload, changes []byte
		if err := rows.Scan(&row.action, &row.result, &payload, &changes); err != nil {
			t.Fatalf("scan module audit: %v", err)
		}
		row.changes = audittest.DecodeChanges(t, changes)
		if err := json.Unmarshal(payload, &row.payload); err != nil {
			t.Fatalf("decode module audit: %v", err)
		}
		result = append(result, row)
	}
	return result
}

// Acceptance (PA-15): a module granted by the lease is listed and passes the
// API check; re-signing the lease without it hides it, the API check is denied
// with ErrFeatureDenied (HTTP entitlement_feature_denied) and an audit event
// records the change with the module's declared revoke behavior; re-granting
// restores it.
func TestModuleGrantRevokeAndRestore(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.moduleLease(1, testModule, "pack.crs"), fixture.now)

	grants := fixture.grantedModules(t)
	if grants.Status != string(entitlement.StatusValid) || grants.LeaseSerial != 1 ||
		!reflect.DeepEqual(grants.Codes, []string{testModule, "pack.crs"}) {
		t.Fatalf("GrantedModules(granted) = %+v", grants)
	}
	if err := fixture.checkModule(t, testModule, "granted"); err != nil {
		t.Fatalf("CheckModule(granted) error = %v", err)
	}

	fixture.install(t, fixture.moduleLease(2, "pack.crs"), fixture.now)
	grants = fixture.grantedModules(t)
	if !reflect.DeepEqual(grants.Codes, []string{"pack.crs"}) || grants.Has(testModule) || !grants.Has("pack.crs") {
		t.Fatalf("GrantedModules(revoked) = %+v", grants)
	}
	if err := fixture.checkModule(t, testModule, "revoked"); !errors.Is(err, ErrFeatureDenied) {
		t.Fatalf("CheckModule(revoked) error = %v, want ErrFeatureDenied", err)
	}

	fixture.install(t, fixture.moduleLease(3, testModule, "pack.crs", "pack.selfwaf"), fixture.now)
	if grants := fixture.grantedModules(t); !grants.Has(testModule) || !grants.Has("pack.selfwaf") {
		t.Fatalf("GrantedModules(restored) = %+v", grants)
	}
	if err := fixture.checkModule(t, testModule, "restored"); err != nil {
		t.Fatalf("CheckModule(restored) error = %v", err)
	}
	// Re-installing the same serial changes nothing and writes no event.
	fixture.install(t, fixture.moduleLease(3, testModule, "pack.crs", "pack.selfwaf"), fixture.now)

	audits := fixture.moduleAudits(t)
	if len(audits) != 3 {
		t.Fatalf("module audits = %d, want 3 (initial grant, revoke, restore): %+v", len(audits), audits)
	}
	revoke := audits[1]
	if revoke.result != "success" || revoke.payload["actor"] != "system" ||
		revoke.payload["scope"] != "platform" {
		t.Fatalf("revoke audit = %+v", revoke)
	}
	removedChange, _ := audittest.Find(revoke.changes, "modules_removed")
	removed, _ := removedChange.After.([]any)
	if len(removed) != 1 {
		t.Fatalf("revoke modules_removed = %#v", revoke.changes)
	}
	entry, _ := removed[0].(map[string]any)
	if entry["code"] != testModule || entry["revoke_behavior"] != "" {
		t.Fatalf("revoke removed entry = %#v (test module is not in the catalog)", entry)
	}
	modules, _ := audittest.Find(revoke.changes, "modules")
	serial, _ := audittest.Find(revoke.changes, "lease_serial")
	if !reflect.DeepEqual(modules.Before, []any{testModule, "pack.crs"}) ||
		!reflect.DeepEqual(modules.After, []any{"pack.crs"}) ||
		serial.Before != float64(1) || serial.After != float64(2) {
		t.Fatalf("revoke changes = %#v", revoke.changes)
	}
	addedChange, _ := audittest.Find(audits[2].changes, "modules_added")
	added, _ := addedChange.After.([]any)
	if len(added) != 2 {
		t.Fatalf("restore modules_added = %#v", audits[2].changes)
	}
	selfwaf, _ := added[1].(map[string]any)
	if selfwaf["code"] != "pack.selfwaf" || selfwaf["revoke_behavior"] != string(entitlement.RevokeRemoveExisting) {
		t.Fatalf("restore catalog entry = %#v", selfwaf)
	}
}

func TestGrantedModulesFailsClosed(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	if grants := fixture.grantedModules(t); grants.Status != StatusUninstalled || len(grants.Codes) != 0 {
		t.Fatalf("GrantedModules(no lease) = %+v", grants)
	}
	lease := fixture.moduleLease(1, testModule)
	lease.NotBefore = fixture.now.Add(-3 * time.Hour).Unix()
	lease.ExpiresAt = fixture.now.Add(-30 * time.Minute).Unix()
	lease.GraceUntil = fixture.now.Add(time.Hour).Unix()
	fixture.install(t, lease, fixture.now)
	// Grace keeps modules usable while the license service is unreachable;
	// expired denies.
	grants := fixture.grantedModules(t)
	if grants.Status != string(entitlement.StatusGrace) || len(grants.Codes) != 1 || grants.Codes[0] != testModule {
		t.Fatalf("GrantedModules(grace) = %+v, want %s", grants, testModule)
	}
	if err := fixture.checkModule(t, testModule, "grace"); err != nil {
		t.Fatalf("CheckModule(grace) error = %v", err)
	}
	expired := fixture.moduleLease(2, testModule)
	expired.NotBefore = fixture.now.Add(-3 * time.Hour).Unix()
	expired.ExpiresAt = fixture.now.Add(-2 * time.Hour).Unix()
	expired.GraceUntil = fixture.now.Add(-time.Hour).Unix()
	fixture.install(t, expired, fixture.now)
	if grants := fixture.grantedModules(t); grants.Status != string(entitlement.StatusExpired) || len(grants.Codes) != 0 {
		t.Fatalf("GrantedModules(expired) = %+v", grants)
	}
	if err := fixture.checkModule(t, testModule, "expired"); !errors.Is(err, ErrStateDenied) {
		t.Fatalf("CheckModule(expired) error = %v", err)
	}
}

func TestCheckModuleRejectsNonModuleCode(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.moduleLease(1), fixture.now)
	if err := fixture.checkModule(t, FeatureExtensionsWebhooks, "plain"); err == nil || IsDenial(err) {
		t.Fatalf("CheckModule(non-module code) error = %v, want a programming error", err)
	}
	if err := fixture.checkModule(t, "module.", "malformed"); err == nil || IsDenial(err) {
		t.Fatalf("CheckModule(malformed) error = %v", err)
	}
}

// The first install runs before bootstrap creates the platform scope; the
// module audit is skipped there instead of failing the install.
func TestInstallWithoutPlatformScopeSkipsModuleAudit(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM access_scopes WHERE kind='platform'`); err != nil {
		t.Fatalf("drop platform scope: %v", err)
	}
	fixture.install(t, fixture.moduleLease(1, testModule), fixture.now)
	if audits := fixture.moduleAudits(t); len(audits) != 0 {
		t.Fatalf("module audits without platform scope = %+v", audits)
	}
}

// AuthorizeModule is the one transactional module gate every caller uses (the
// HTTP requireModule wrapper, aggregatededge.EntitlementGate): a denial is
// returned as the denial and its audit event is committed; a grant returns
// nil; a non-module code is a programming error, not a denial.
func TestAuthorizeModuleCommitsDenialAudit(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.moduleLease(1), fixture.now)
	check := ModuleCheck{
		TargetScopeID: fixture.targetScope, ActorScopeID: fixture.actorScope, ActorUserID: fixture.actorUser,
		ResourceType: "module_probe", ResourceID: fixture.resourceID, RequestID: "authorize-denied",
		Operation: "module_probe.use", Module: testModule,
	}
	if err := fixture.guard().AuthorizeModule(t.Context(), fixture.pool, check); !errors.Is(err, ErrFeatureDenied) {
		t.Fatalf("AuthorizeModule(not granted) error = %v, want ErrFeatureDenied", err)
	}
	var denials int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE request_id='authorize-denied'
		AND action='entitlement.guard.reject' AND payload->>'feature'=$1`, testModule).Scan(&denials); err != nil || denials != 1 {
		t.Fatalf("committed denial audits = %d, %v", denials, err)
	}

	fixture.install(t, fixture.moduleLease(2, testModule), fixture.now)
	check.RequestID = "authorize-granted"
	if err := fixture.guard().AuthorizeModule(t.Context(), fixture.pool, check); err != nil {
		t.Fatalf("AuthorizeModule(granted) error = %v", err)
	}
	check.Module, check.RequestID = FeatureExtensionsWebhooks, "authorize-plain"
	if err := fixture.guard().AuthorizeModule(t.Context(), fixture.pool, check); err == nil || IsDenial(err) {
		t.Fatalf("AuthorizeModule(non-module code) error = %v, want a programming error", err)
	}
}
