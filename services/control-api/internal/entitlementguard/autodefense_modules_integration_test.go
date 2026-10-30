package entitlementguard

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
)

// ADR 0010 Q1/Q2: a lease with only the free module.autodefense
// passes the module.autodefense gate and is denied module.autodefense.auto
// (audited); granting the paid code opens it.
func TestAutoDefenseModuleGates(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.moduleLease(1, entitlement.ModuleAutoDefense), fixture.now)
	check := ModuleCheck{
		TargetScopeID: fixture.targetScope, ActorScopeID: fixture.actorScope, ActorUserID: fixture.actorUser,
		ResourceType: "autodefense_site", ResourceID: fixture.resourceID, RequestID: "autodefense-free",
		Operation: "autodefense.observe", Module: entitlement.ModuleAutoDefense,
	}
	if err := fixture.guard().AuthorizeModule(t.Context(), fixture.pool, check); err != nil {
		t.Fatalf("AuthorizeModule(module.autodefense) = %v", err)
	}
	check.Module, check.RequestID, check.Operation = entitlement.ModuleAutoDefenseAuto, "autodefense-auto-denied", "autodefense.mitigate"
	if err := fixture.guard().AuthorizeModule(t.Context(), fixture.pool, check); !errors.Is(err, ErrFeatureDenied) {
		t.Fatalf("AuthorizeModule(module.autodefense.auto, unlicensed) = %v, want ErrFeatureDenied", err)
	}
	var denials int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE request_id='autodefense-auto-denied'
		AND action='entitlement.guard.reject' AND payload->>'feature'=$1`, entitlement.ModuleAutoDefenseAuto).Scan(&denials); err != nil || denials != 1 {
		t.Fatalf("denial audits = %d, %v", denials, err)
	}

	fixture.install(t, fixture.moduleLease(2, entitlement.ModuleAutoDefense, entitlement.ModuleAutoDefenseAuto), fixture.now)
	check.RequestID = "autodefense-auto-granted"
	if err := fixture.guard().AuthorizeModule(t.Context(), fixture.pool, check); err != nil {
		t.Fatalf("AuthorizeModule(module.autodefense.auto, licensed) = %v", err)
	}
	audits := fixture.moduleAudits(t)
	if len(audits) == 0 {
		t.Fatal("module change not audited")
	}
	addedChange, _ := audittest.Find(audits[len(audits)-1].changes, "modules_added")
	added, _ := addedChange.After.([]any)
	entry, _ := func() (map[string]any, bool) {
		if len(added) != 1 {
			return nil, false
		}
		m, ok := added[0].(map[string]any)
		return m, ok
	}()
	if entry["code"] != entitlement.ModuleAutoDefenseAuto || entry["revoke_behavior"] != string(entitlement.RevokeDrainExisting) {
		t.Fatalf("grant modules_added = %#v", audits[len(audits)-1].changes)
	}
}
