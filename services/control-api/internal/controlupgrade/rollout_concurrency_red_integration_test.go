//go:build integration

package controlupgrade

import "testing"

func TestConcurrentActiveBatchStatusReceiptsShareDispatchRevision(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	dispatchRevision := plan.Revision

	// Successful receipts must carry active-probe evidence (plan.go ApplyPlanHealth);
	// build them like every other success receipt, both at the same dispatch revision.
	first := currentPlanHealth(plan, nodeID(2), true)
	first.ID = nodeID(901)
	second := currentPlanHealth(plan, nodeID(3), true)
	second.ID = nodeID(902)
	if first.DispatchRevision != dispatchRevision || second.DispatchRevision != dispatchRevision {
		t.Fatalf("dispatch revisions = %d/%d, want %d", first.DispatchRevision, second.DispatchRevision, dispatchRevision)
	}

	firstResult := mustPlanHealth(t, plan, first)
	// A row-locked durable store must serialize both receipts without treating their shared dispatch revision as stale.
	secondResult, err := ApplyPlanHealth(firstResult.Plan, second)
	if err != nil {
		t.Fatalf("second receipt for dispatch revision %d error = %v; durable command binding must accept both", dispatchRevision, err)
	}
	if secondResult.Plan.Revision != dispatchRevision+2 ||
		secondResult.Plan.NodeStates[nodeID(2)] != NodeHealthy ||
		secondResult.Plan.NodeStates[nodeID(3)] != NodeHealthy {
		t.Fatalf("serialized same-dispatch receipts = %#v", secondResult.Plan)
	}
}
