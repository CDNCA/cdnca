package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
)

const revisionTestScope = "5c000000-0000-4000-8000-000000000001"

// fakeDynamicRuntime stands in for dynroute.Runtime: Apply activates the
// input's version of the scope (what ScopeVersion then reports).
type fakeDynamicRuntime struct {
	active  map[string]string
	applies int
}

func (f *fakeDynamicRuntime) apply(_ context.Context, input dynroute.Input) (dynroute.Result, error) {
	f.applies++
	f.active = map[string]string{}
	for scope, version := range input.ScopeVersions {
		f.active[scope] = version
	}
	return dynroute.Result{}, nil
}

func (f *fakeDynamicRuntime) version(scope string) string { return f.active[scope] }

func revisionTestManager(t *testing.T) (*dynamicRoutingManager, *fakeDynamicRuntime) {
	t.Helper()
	root := t.TempDir()
	objects, err := objectstore.Open(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeDynamicRuntime{}
	manager := &dynamicRoutingManager{objects: objects, root: filepath.Join(root, "scopes"), now: func() time.Time {
		return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	}, apply: runtime.apply, activeVersion: runtime.version}
	if err := os.MkdirAll(manager.root, 0o700); err != nil {
		t.Fatal(err)
	}
	return manager, runtime
}

func revisionRelease(version string, revision int64, root string) gatewayclient.DynamicRoutingRelease {
	return gatewayclient.DynamicRoutingRelease{ConfigurationScopeID: revisionTestScope, ConfigVersionID: version,
		RootSHA256: root, SourceRevision: revision}
}

const (
	versionR1 = "c1000000-0000-4000-8000-000000000001"
	versionR2 = "c2000000-0000-4000-8000-000000000002"
	versionR3 = "c3000000-0000-4000-8000-000000000003"
	rootR1    = "1111111111111111111111111111111111111111111111111111111111111111"
	rootR2    = "2222222222222222222222222222222222222222222222222222222222222222"
	rootR2b   = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	rootR3    = "3333333333333333333333333333333333333333333333333333333333333333"
)

func applyRevision(t *testing.T, manager *dynamicRoutingManager, deploymentID string, release gatewayclient.DynamicRoutingRelease) deployment.Result {
	t.Helper()
	result, err := manager.ApplyDynamicRouting(t.Context(), deploymentID, 1, release)
	if err != nil {
		t.Fatalf("apply %s: %v", deploymentID, err)
	}
	return result
}

func refused(result deployment.Result, code string) bool {
	return result.State == deployment.StateFailed && result.RunningConfigUnchanged && result.ErrorCode == code
}

// DYNROUTE-LATE-APPLY-REVISION-01: a late older apply, or another root under
// the accepted revision, is refused before activation; the same root again
// (a new deployment or attempt: retry, reconcile) applies.
func TestDynamicRoutingRefusesLateOlderApply(t *testing.T) {
	manager, runtime := revisionTestManager(t)
	if r := applyRevision(t, manager, "d0000000-0000-4000-8000-000000000002", revisionRelease(versionR2, 2, rootR2)); r.State != deployment.StateHealthy {
		t.Fatalf("revision 2 = %+v", r)
	}
	applies := runtime.applies
	late := applyRevision(t, manager, "d0000000-0000-4000-8000-000000000001", revisionRelease(versionR1, 1, rootR1))
	if !refused(late, dynamicRoutingStaleRevision) || runtime.applies != applies || runtime.version(revisionTestScope) != versionR2 {
		t.Fatalf("late revision 1 = %+v, applies %d, active %s", late, runtime.applies-applies, runtime.version(revisionTestScope))
	}
	conflict := applyRevision(t, manager, "d0000000-0000-4000-8000-0000000000b2", revisionRelease(versionR2, 2, rootR2b))
	if !refused(conflict, dynamicRoutingRevisionConflict) || runtime.applies != applies {
		t.Fatalf("revision 2 with another root = %+v", conflict)
	}
	again := applyRevision(t, manager, "d0000000-0000-4000-8000-0000000000a2", revisionRelease(versionR2, 2, rootR2))
	if again.State != deployment.StateHealthy {
		t.Fatalf("same root under a new deployment = %+v", again)
	}
	pointers, err := manager.ScopePointers(revisionTestScope)
	if err != nil || pointers.Current != versionR2 {
		t.Fatalf("pointers %+v %v", pointers, err)
	}
	// the refusal is the deployment's recorded result: redelivery returns it
	if r, _ := manager.ApplyDynamicRouting(t.Context(), "d0000000-0000-4000-8000-000000000001", 1, revisionRelease(versionR1, 1, rootR1)); !refused(r, dynamicRoutingStaleRevision) {
		t.Fatalf("redelivered refusal = %+v", r)
	}
}

// An explicit rollback runs the older release but keeps the mark: a late
// copy of the release rolled away from does not undo it, an older one is
// still stale, and only a newer revision goes forward.
func TestDynamicRoutingRollbackKeepsTheMark(t *testing.T) {
	manager, runtime := revisionTestManager(t)
	applyRevision(t, manager, "d1000000-0000-4000-8000-000000000001", revisionRelease(versionR1, 1, rootR1))
	applyRevision(t, manager, "d1000000-0000-4000-8000-000000000002", revisionRelease(versionR2, 2, rootR2))
	rollback, err := manager.Process(t.Context(), deployment.Command{DeploymentID: "d1000000-0000-4000-8000-0000000000f1", Attempt: 1,
		Action: deployment.ActionRollback, ConfigVersionID: versionR1, ScopeID: revisionTestScope})
	if err != nil || rollback.State != deployment.StateReverted || runtime.version(revisionTestScope) != versionR1 {
		t.Fatalf("rollback = %+v %v, active %s", rollback, err, runtime.version(revisionTestScope))
	}
	if r := applyRevision(t, manager, "d1000000-0000-4000-8000-0000000000a2", revisionRelease(versionR2, 2, rootR2)); !refused(r, dynamicRoutingRolledBack) ||
		runtime.version(revisionTestScope) != versionR1 {
		t.Fatalf("late copy of the rolled back release = %+v", r)
	}
	if r := applyRevision(t, manager, "d1000000-0000-4000-8000-0000000000a1", revisionRelease(versionR1, 1, rootR1)); !refused(r, dynamicRoutingStaleRevision) {
		t.Fatalf("older apply after rollback = %+v", r)
	}
	if r := applyRevision(t, manager, "d1000000-0000-4000-8000-000000000003", revisionRelease(versionR3, 3, rootR3)); r.State != deployment.StateHealthy ||
		runtime.version(revisionTestScope) != versionR3 {
		t.Fatalf("newer revision after rollback = %+v", r)
	}
}

// DYNROUTE-SCOPE-SAVE-LOSS-01: activated, then the scope journal cannot be
// saved. The result says the release runs (healthy with a failed
// maintenance check, not "unchanged"); once the journal is writable the next
// load makes it current without activating again.
func TestDynamicRoutingJournalLossAfterActivation(t *testing.T) {
	manager, runtime := revisionTestManager(t)
	applyRevision(t, manager, "d2000000-0000-4000-8000-000000000001", revisionRelease(versionR1, 1, rootR1))
	realApply := runtime.apply
	manager.apply = func(ctx context.Context, input dynroute.Input) (dynroute.Result, error) {
		result, err := realApply(ctx, input)
		if err := os.Chmod(manager.root, 0o500); err != nil { // the journal directory turns read-only after activation
			t.Fatal(err)
		}
		return result, err
	}
	t.Cleanup(func() { _ = os.Chmod(manager.root, 0o700) })
	result, err := manager.ApplyDynamicRouting(t.Context(), "d2000000-0000-4000-8000-000000000002", 1, revisionRelease(versionR2, 2, rootR2))
	if err != nil || result.State != deployment.StateHealthy || result.RunningConfigUnchanged ||
		result.Transitions[len(result.Transitions)-1].MaintenanceFailure == "" {
		t.Fatalf("journal loss = %+v %v", result, err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only directory")
	}
	// What runs is what the pointers say, before the journal is repaired.
	if pointers, err := manager.ScopePointers(revisionTestScope); err != nil || pointers.Current != versionR2 {
		t.Fatalf("pointers after journal loss = %+v %v", pointers, err)
	}
	if err := os.Chmod(manager.root, 0o700); err != nil {
		t.Fatal(err)
	}
	manager.apply = realApply
	applies := runtime.applies
	again, err := manager.ApplyDynamicRouting(t.Context(), "d2000000-0000-4000-8000-000000000002", 1, revisionRelease(versionR2, 2, rootR2))
	if err != nil || again.State != deployment.StateHealthy || again.RunningConfigUnchanged || runtime.applies != applies {
		t.Fatalf("redelivery after repair = %+v %v, applies %d", again, err, runtime.applies-applies)
	}
	scope, err := manager.load(revisionTestScope)
	if err != nil || scope.Pending != nil || scope.Current.ConfigVersionID != versionR2 || scope.Accepted.SourceRevision != 2 {
		t.Fatalf("repaired journal = %+v %v", scope, err)
	}
	// the mark survived: the late older apply is refused
	if r := applyRevision(t, manager, "d2000000-0000-4000-8000-0000000000a1", revisionRelease(versionR1, 1, rootR1)); !refused(r, dynamicRoutingStaleRevision) {
		t.Fatalf("late apply after repair = %+v", r)
	}
}

// The intent cannot be saved before activation: nothing switches and the
// error is returned (the client records a failure, running config unchanged).
func TestDynamicRoutingIntentNotSavedSwitchesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only directory")
	}
	manager, runtime := revisionTestManager(t)
	if err := os.Chmod(manager.root, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(manager.root, 0o700) })
	if _, err := manager.ApplyDynamicRouting(t.Context(), "d3000000-0000-4000-8000-000000000001", 1, revisionRelease(versionR1, 1, rootR1)); err == nil ||
		runtime.applies != 0 {
		t.Fatalf("apply without a journal: %v, applies %d", err, runtime.applies)
	}
}
