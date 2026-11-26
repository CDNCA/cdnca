package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
)

// the first generation activated,
// failed its health wait and its compensation failed before switching
// anything; it kept serving while the scope journal had no current release,
// so the scope reported nothing the control plane could reconcile with and
// its access records had no scope. The release becomes current only when the
// active index and every live worker are verifiably on that generation.

func rollbackFailedApply(generation uint64) func(context.Context, dynroute.Input) (dynroute.Result, error) {
	return func(context.Context, dynroute.Input) (dynroute.Result, error) {
		return dynroute.Result{}, &dynroute.RollbackFailedError{Generation: generation, Err: context.Canceled,
			RollbackErr: errors.New("site index: control conflict: generation 1 has no single-step rollback")}
	}
}

func TestRollbackFailureKeepsTheServingReleaseAsCurrent(t *testing.T) {
	manager, _ := revisionTestManager(t)
	manager.apply = rollbackFailedApply(1)
	var asked []uint64
	manager.serves = func(_ context.Context, generation uint64) bool {
		asked = append(asked, generation)
		return generation == 1
	}
	const deploymentID = "d6000000-0000-4000-8000-000000000001"
	result := applyRevision(t, manager, deploymentID, revisionRelease(versionR1, 10, rootR1))
	if result.State != deployment.StateRollbackFailed {
		t.Fatalf("result = %s, want rollback_failed kept", result.State)
	}
	if len(asked) != 1 || asked[0] != 1 {
		t.Fatalf("serving checks = %v, want generation 1 once", asked)
	}
	pointers, err := manager.ScopePointers(revisionTestScope)
	if err != nil || pointers.Current != versionR1 || pointers.CurrentDigest != rootR1 || pointers.Previous != "" {
		t.Fatalf("pointers = (%+v, %v), want the serving release current", pointers, err)
	}
	if !manager.ServingAfterRollbackFailure(deploymentID, 1) || manager.ServingAfterRollbackFailure(deploymentID, 2) {
		t.Fatal("the serving release is not marked as kept after its rollback failure (or another attempt is)")
	}
	found, ok, err := manager.Lookup(deploymentID)
	if err != nil || !ok || found.State != deployment.StateRollbackFailed {
		t.Fatalf("recorded result = (%+v, %v, %v), want the failure kept for audit", found, ok, err)
	}
	// Its records wait: the control plane has not confirmed the release.
	scope, err := manager.load(revisionTestScope)
	if err != nil || scope.ServingAfterRollbackFailure == nil {
		t.Fatalf("journal = (%+v, %v)", scope, err)
	}

	// The next activated apply replaces it and clears the mark.
	manager.apply = (&fakeDynamicRuntime{}).apply
	applyRevision(t, manager, "d6000000-0000-4000-8000-000000000002", revisionRelease(versionR2, 14, rootR2))
	if manager.ServingAfterRollbackFailure(deploymentID, 1) {
		t.Fatal("the mark outlived the next accepted release")
	}
	if pointers, _ := manager.ScopePointers(revisionTestScope); pointers.Current != versionR2 || pointers.Previous != versionR1 {
		t.Fatalf("pointers after the next release = %+v", pointers)
	}
}

func TestRollbackFailureLeavesTheScopeWhenTheGenerationIsNotVerified(t *testing.T) {
	for name, serves := range map[string]func(context.Context, uint64) bool{
		"index or workers on another generation": func(context.Context, uint64) bool { return false },
		"no verifier":                            nil,
	} {
		t.Run(name, func(t *testing.T) {
			manager, _ := revisionTestManager(t)
			manager.apply = rollbackFailedApply(1)
			manager.serves = serves
			const deploymentID = "d7000000-0000-4000-8000-000000000001"
			if result := applyRevision(t, manager, deploymentID, revisionRelease(versionR1, 10, rootR1)); result.State != deployment.StateRollbackFailed {
				t.Fatalf("result = %s", result.State)
			}
			if pointers, err := manager.ScopePointers(revisionTestScope); err != nil || pointers.Current != "" {
				t.Fatalf("pointers = (%+v, %v), want no current release", pointers, err)
			}
			if manager.ServingAfterRollbackFailure(deploymentID, 1) {
				t.Fatal("an unverified release is marked as serving")
			}
		})
	}
	// A reverted apply is not a rollback failure: nothing is kept.
	manager, _ := revisionTestManager(t)
	manager.apply = func(context.Context, dynroute.Input) (dynroute.Result, error) {
		return dynroute.Result{}, &dynroute.RevertedError{Generation: 2, RevertedTo: 1, Err: context.Canceled}
	}
	manager.serves = func(context.Context, uint64) bool { return true }
	applyRevision(t, manager, "d7000000-0000-4000-8000-000000000002", revisionRelease(versionR1, 10, rootR1))
	if pointers, _ := manager.ScopePointers(revisionTestScope); pointers.Current != "" {
		t.Fatalf("reverted apply pointers = %+v", pointers)
	}
}

// A release current only because it kept serving maps no site for telemetry.
func TestServingAfterRollbackFailureMapsNoTelemetrySite(t *testing.T) {
	manager, _ := revisionTestManager(t)
	digest, raw := dynamicTestSite(t, revisionTestScope, "a0000000-0000-4000-8000-0000000000aa", "a.example.test")
	if err := manager.objects.Put(digest, raw); err != nil {
		t.Fatal(err)
	}
	scope := dynamicRoutingScope{Current: &dynamicRoutingRelease{ConfigVersionID: versionR1, RootSHA256: digest, Sites: []string{digest}},
		ServingAfterRollbackFailure: &dynamicRoutingServing{DeploymentID: "d8000000-0000-4000-8000-000000000001", Attempt: 1}}
	if err := manager.save(revisionTestScope, scope); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.ScopeForSite("a0000000-0000-4000-8000-0000000000aa"); ok {
		t.Fatal("an unconfirmed serving release maps its site")
	}
	scope.ServingAfterRollbackFailure = nil
	if err := manager.save(revisionTestScope, scope); err != nil {
		t.Fatal(err)
	}
	if got, ok := manager.ScopeForSite("a0000000-0000-4000-8000-0000000000aa"); !ok || got != revisionTestScope {
		t.Fatalf("accepted release site scope = %q, %v", got, ok)
	}
}
