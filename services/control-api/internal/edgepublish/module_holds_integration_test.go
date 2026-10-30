//go:build integration

package edgepublish_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Acceptance: revoking a module the scope's published
// release uses leaves the scope pending republication (the nodes keep the
// release, nothing is republished, the page lists the module, audited; the
// publication gate refusal is TestPublishRefusesSourceUsingUngrantedModule);
// granting it again
// clears the mark and the system channel republishes the scope (trigger
// module_entitlement), audited.
func TestModuleRevocationMarksPendingAndRestoreRepublishes(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	node := scope.AddNode(t, 6)
	grants := &edgepublish.ModuleGrants{}
	grants.Set(edgepublish.ModuleProbeCode)
	requirements := scope.UseProbeModule(t, grants)
	watcher, err := edgeautopublish.NewModuleWatcher(scope.Pool, grants, requirements, audit.New(scope.Pool), 0)
	if err != nil {
		t.Fatal(err)
	}
	sweep := func() edgeautopublish.ModuleSweepResult {
		t.Helper()
		result, err := watcher.SweepOnce(t.Context())
		if err != nil {
			t.Fatalf("module sweep: %v", err)
		}
		return result
	}
	holds := func() []edgepublish.ModulePublicationHold {
		t.Helper()
		var result []edgepublish.ModulePublicationHold
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			var err error
			result, err = edgepublish.ModulePublicationHoldsTx(t.Context(), tx, scope.ScopeID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}

	if result := sweep(); !reflect.DeepEqual(result.Granted, []string{edgepublish.ModuleProbeCode}) ||
		len(result.Pending)+len(result.Republished) != 0 {
		t.Fatalf("baseline sweep = %+v", result)
	}
	if err := scope.PublishManually(t, "module-before-revoke", node); err != nil {
		t.Fatalf("publish while granted: %v", err)
	}
	scope.SettleDeployments(t)
	published := scope.LatestPublication(t)

	grants.Set()
	result := sweep()
	if !reflect.DeepEqual(result.Revoked, []string{edgepublish.ModuleProbeCode}) || !slices.Equal(result.Pending,
		[]uuid.UUID{scope.ScopeID}) || len(result.Republished) != 0 {
		t.Fatalf("revoke sweep = %+v", result)
	}
	if got := holds(); len(got) != 1 || got[0].Module != edgepublish.ModuleProbeCode ||
		got[0].SourceRevision != published.SourceRevision {
		t.Fatalf("holds after revoke = %+v", got)
	}
	if again := sweep(); len(again.Pending)+len(again.Revoked) != 0 {
		t.Fatalf("unchanged grant sweep = %+v", again)
	}
	if scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`) != 0 ||
		scope.LatestPublication(t).SourceRevision != published.SourceRevision {
		t.Fatal("revocation must not republish the scope")
	}
	// The before -> after summary is in the changes column (unified log).
	pendingAudit := audittest.Last(t, scope.Pool, `scope_id=$1 AND action=$2 AND result='success'`,
		scope.ScopeID, edgepublish.ModulePendingRepublicationAction)
	revoked, _ := pendingAudit.Change("revoked_modules")
	pendingFlag, _ := pendingAudit.Change("pending_republication")
	if pendingAudit.Payload["actor"] != "system" ||
		!reflect.DeepEqual(revoked.After, []any{edgepublish.ModuleProbeCode}) ||
		pendingFlag.Before != false || pendingFlag.After != true {
		t.Fatalf("pending audit payload = %#v changes = %#v", pendingAudit.Payload, pendingAudit.Changes)
	}
	grants.Set(edgepublish.ModuleProbeCode)
	result = sweep()
	if !reflect.DeepEqual(result.Granted, []string{edgepublish.ModuleProbeCode}) ||
		!slices.Equal(result.Republished, []uuid.UUID{scope.ScopeID}) {
		t.Fatalf("restore sweep = %+v", result)
	}
	if got := holds(); len(got) != 0 {
		t.Fatalf("holds after restore = %+v", got)
	}
	restoreAudit := audittest.Last(t, scope.Pool, `scope_id=$1 AND action=$2`, scope.ScopeID, edgepublish.ModuleRestoredAction)
	if restored, _ := restoreAudit.Change("restored_modules"); !reflect.DeepEqual(restored.After,
		[]any{edgepublish.ModuleProbeCode}) {
		t.Fatalf("restore audit changes = %#v", restoreAudit.Changes)
	}
	if runs := scope.Run(t); runs == 0 {
		t.Fatal("restore did not queue a system republication")
	}
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomePublished ||
		!slices.Contains(attempt.Triggers, edgepublish.SystemTriggerModuleEntitlement) {
		raw, _ := json.Marshal(attempt)
		t.Fatalf("restore attempt = %s", raw)
	}
	if latest := scope.LatestPublication(t); latest.SourceRevision <= published.SourceRevision ||
		!slices.Equal(latest.NodeIDs, []uuid.UUID{node}) {
		t.Fatalf("restore publication = rev %d nodes %v", latest.SourceRevision, latest.NodeIDs)
	}
}
