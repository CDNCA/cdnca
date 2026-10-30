//go:build integration

package securityactivation

import (
	"testing"

	"github.com/google/uuid"
)

// N2 (73, 10-23): after the expand rollout was created and before the expand
// node was healthy, every worker pass reached actionExpand again with its own
// request ID; CreateRolloutTx replayed the "expand.<candidate>" key with a new
// digest, returned ErrIdempotencyConflict wrapped as a dependency error, and
// the worker stopped control-api (20 restarts in two minutes). A pass in that
// window must wait instead.
func TestReconcileWaitsWhileExpandRolloutRuns(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "expand-wait",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	candidate := started.Candidate
	if len(candidate.ExpandNodeIDs) == 0 {
		t.Fatal("fixture has no expand node")
	}
	markProductionPhaseHealthy(t, fixture, candidate, "canary")
	expanded, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "expand-wait-1"))
	if err != nil || expanded.Action != string(actionExpand) || expanded.Candidate.Status != StatusCanary {
		t.Fatalf("first Reconcile = (%+v, %v)", expanded, err)
	}
	// A later worker pass: new idempotency key and request ID, expand node
	// still deploying.
	waited, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "expand-wait-2"))
	if err != nil || waited.Action != string(actionWait) || waited.Candidate.Status != StatusCanary {
		t.Fatalf("Reconcile while expand runs = (%+v, %v), want wait", waited, err)
	}
	assertPhaseCounts(t, fixture.pool, candidate.ID, 2, 1)
	markProductionPhaseHealthy(t, fixture, candidate, "expand")
	final, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "expand-wait-3"))
	if err != nil || final.Action != string(actionPromote) || final.Candidate.Status != StatusPromoted {
		t.Fatalf("expand Reconcile = (%+v, %v)", final, err)
	}
}
