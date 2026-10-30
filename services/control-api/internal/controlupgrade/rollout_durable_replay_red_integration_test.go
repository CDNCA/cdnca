//go:build integration

package controlupgrade

import (
	"errors"
	"testing"
)

func TestDurableEventReplayRejectsForgedCompletedSnapshot(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	health := currentPlanHealth(plan, nodeID(1), true)
	event := commitPlanEvent(&plan, PlanEvent{
		From: PlanCanary, To: PlanCompleted, Action: "health_succeeded", Reason: "healthy",
		BatchID: plan.Batches[0].ID, NodeID: health.NodeID,
	})
	plan.HealthReceipts = append(plan.HealthReceipts, PlanHealthReceipt{Health: health, Event: event})
	plan.State = PlanCompleted
	plan.Completion = CompletionUpgraded
	plan.ActiveBatch = -1
	for nodeID := range plan.NodeStates {
		plan.NodeStates[nodeID] = NodeHealthy
	}

	if validRolloutPlan(plan) {
		t.Fatal("accepted forged completion without replaying node 2-4 status receipts")
	}
}

func TestAutomaticRollbackRequiresSettledBatchAndDurableSystemCommandOutbox(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	failure := currentPlanHealth(plan, nodeID(2), false)
	failure.Code = "health_probe_failed"
	plan = mustPlanHealth(t, plan, failure).Plan
	rollback := planCommand(PlanRollback, plan.Revision, "automatic_policy_requested")
	if _, err := ApplyPlanCommand(plan, rollback); !errors.Is(err, ErrPlanBlocked) {
		t.Fatalf("automatic rollback with in-flight sibling error = %v, want blocked", err)
	}

	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(3), true)).Plan
	for _, receipt := range plan.CommandReceipts {
		if receipt.Command.Action == PlanRollback {
			return
		}
	}
	t.Fatal("settled batch has no durable system rollback command/outbox transaction")
}
