package controlupgrade

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

func TestNewRolloutPlanFreezesCanaryAndGroupBatches(t *testing.T) {
	input := validRolloutPlanInput()
	plan, err := NewRolloutPlan(input)
	if err != nil {
		t.Fatalf("NewRolloutPlan() error = %v", err)
	}
	want := []PlanBatch{
		{GroupID: "canary", Canary: true, NodeIDs: []string{nodeID(1)}},
		{GroupID: "primary", NodeIDs: []string{nodeID(2), nodeID(3)}},
		{GroupID: "primary", NodeIDs: []string{nodeID(4)}},
	}
	if plan.SchemaVersion != RolloutPlanSchemaVersionV2 || plan.State != PlanQueued || plan.Revision != 1 ||
		plan.ActiveBatch != -1 || !plan.AutomaticRollback || len(plan.Batches) != len(want) {
		t.Fatalf("NewRolloutPlan() = %#v", plan)
	}
	for index := range want {
		batch := plan.Batches[index]
		want[index].ID = batch.ID
		if _, err := uuid.Parse(batch.ID); err != nil || !reflect.DeepEqual(batch, want[index]) {
			t.Fatalf("batch %d = %#v, parse error = %v", index, batch, err)
		}
	}
	rebuilt, err := NewRolloutPlan(input)
	if err != nil || !reflect.DeepEqual(rebuilt.Batches, plan.Batches) {
		t.Fatalf("rebuilt batches = (%#v, %v), want stable IDs %#v", rebuilt.Batches, err, plan.Batches)
	}
	input.Groups[0].Targets[0].NodeID = nodeID(9)
	if plan.Batches[0].NodeIDs[0] != nodeID(1) {
		t.Fatal("plan retained caller-owned target storage")
	}
}

func TestNewRolloutPlanRejectsMoreThanTwoCanaryNodes(t *testing.T) {
	input := validRolloutPlanInput()
	input.Groups[0].Targets = append(input.Groups[0].Targets,
		PlanTarget{NodeID: nodeID(5), AgentVersion: "1.5.0", ProtocolVersion: 2},
		PlanTarget{NodeID: nodeID(6), AgentVersion: "1.5.0", ProtocolVersion: 2},
	)
	input.Groups[0].BatchSize = len(input.Groups[0].Targets)
	if _, err := NewRolloutPlan(input); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("three-node canary error = %v, want ErrInvalidPlan", err)
	}
}

func TestRolloutPlanRequiresImmutableRollbackAuthorization(t *testing.T) {
	fields := []struct {
		name  string
		value any
	}{
		{name: "RollbackGrantDigest", value: planDigest(0x41)},
		{name: "RollbackReleaseSequence", value: uint64(7)},
		{name: "RollbackArtifactID", value: nodeID(102)},
		{name: "RollbackSHA256Digest", value: planDigest(0x44)},
	}
	input := validRolloutPlanInput()
	for _, field := range fields {
		value := reflect.ValueOf(&input).Elem().FieldByName(field.name)
		if !value.IsValid() {
			t.Errorf("RolloutPlanInput missing immutable %s", field.name)
			continue
		}
		value.Set(reflect.ValueOf(field.value))
	}
	if t.Failed() {
		return
	}
	plan, err := NewRolloutPlan(input)
	if err != nil {
		t.Fatalf("NewRolloutPlan() error = %v", err)
	}
	planValue := reflect.ValueOf(plan)
	for _, field := range fields {
		value := planValue.FieldByName(field.name)
		if !value.IsValid() || !reflect.DeepEqual(value.Interface(), field.value) {
			t.Errorf("RolloutPlan.%s = %v, want %v", field.name, value, field.value)
		}
	}

	tests := []struct {
		name  string
		field string
		value any
	}{
		{name: "rollback grant mismatch", field: "RollbackGrantDigest", value: planDigest(0x43)},
		{name: "rollback sequence mismatch", field: "RollbackReleaseSequence", value: uint64(8)},
		{name: "rollback artifact", field: "RollbackArtifactID", value: "invalid"},
		{name: "rollback digest", field: "RollbackSHA256Digest", value: "invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := input
			reflect.ValueOf(&invalid).Elem().FieldByName(test.field).Set(reflect.ValueOf(test.value))
			if _, err := NewRolloutPlan(invalid); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("NewRolloutPlan() error = %v", err)
			}
		})
	}
}

func TestRolloutPlanBlocksUnsafeOrIncompatibleExecution(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RolloutPlanInput)
		code PlanBlockerCode
	}{
		{"irreversible migration", func(in *RolloutPlanInput) { in.Safety.IrreversibleMigration = true }, BlockerIrreversibleMigration},
		{"rollback unavailable", func(in *RolloutPlanInput) { in.Safety.RollbackAvailable = false }, BlockerRollbackUnavailable},
		{"agent too old", func(in *RolloutPlanInput) { in.Groups[1].Targets[0].AgentVersion = "0.9.0" }, BlockerAgentIncompatible},
		{"agent too new", func(in *RolloutPlanInput) { in.Groups[1].Targets[0].AgentVersion = "3.0.0" }, BlockerAgentIncompatible},
		{"protocol too old", func(in *RolloutPlanInput) { in.Groups[1].Targets[0].ProtocolVersion = 1 }, BlockerProtocolIncompatible},
		{"protocol too new", func(in *RolloutPlanInput) { in.Groups[1].Targets[0].ProtocolVersion = 4 }, BlockerProtocolIncompatible},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validRolloutPlanInput()
			test.edit(&input)
			plan, err := NewRolloutPlan(input)
			if err != nil {
				t.Fatalf("NewRolloutPlan() error = %v", err)
			}
			if !hasPlanBlocker(plan, test.code) {
				t.Fatalf("blockers = %#v, want %q", plan.Blockers, test.code)
			}
			before := plan
			_, err = ApplyPlanCommand(plan, planCommand(PlanStart, plan.Revision, "start_requested"))
			if !errors.Is(err, ErrPlanBlocked) || !reflect.DeepEqual(plan, before) {
				t.Fatalf("blocked start error = %v, plan mutated=%v", err, !reflect.DeepEqual(plan, before))
			}
		})
	}
}

func TestRolloutPlanRunsCanaryThenFixedBatches(t *testing.T) {
	plan := mustRolloutPlan(t)
	started := mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested"))
	plan = started.Plan
	assertPlanPosition(t, plan, PlanCanary, 0, []string{nodeID(1)})

	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	assertPlanPosition(t, plan, PlanRunning, 1, []string{nodeID(2), nodeID(3)})
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(2), true)).Plan
	if plan.State != PlanRunning || plan.ActiveBatch != 1 {
		t.Fatalf("partial batch = %#v", plan)
	}
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(3), true)).Plan
	assertPlanPosition(t, plan, PlanRunning, 2, []string{nodeID(4)})
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(4), true)).Plan
	if plan.State != PlanCompleted || plan.Completion != CompletionUpgraded || plan.ActiveBatch != -1 {
		t.Fatalf("completed plan = %#v", plan)
	}
}

func TestRolloutPlanHealthFailureStartsAutomaticRollback(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	failedInput := currentPlanHealth(plan, nodeID(1), false)
	failedInput.Code = "health_probe_failed"
	failed := mustPlanHealth(t, plan, failedInput)
	plan = failed.Plan
	if plan.State != PlanRollingBack || plan.ResumeState != "" || len(plan.RollbackBatches) != 1 ||
		plan.NodeStates[nodeID(1)] != NodeDispatched || failed.Event.Action != "health_failed" ||
		failed.Event.To != PlanPaused || failed.Event.Reason != "health_probe_failed" ||
		len(plan.CommandReceipts) != 2 ||
		plan.CommandReceipts[1].Command.Action != PlanRollback ||
		plan.CommandReceipts[1].Command.ExpectedRevision != failed.Event.Revision {
		t.Fatalf("failed canary = %#v event=%#v", plan, failed.Event)
	}

	replay, err := ApplyPlanHealth(plan, failedInput)
	if err != nil || !replay.Replayed || replay.Event != failed.Event {
		t.Fatalf("health replay = (%#v, %v)", replay, err)
	}
	conflict := failedInput
	conflict.Code = "different_failure"
	if _, err := ApplyPlanHealth(plan, conflict); !errors.Is(err, ErrPlanIdempotencyConflict) {
		t.Fatalf("health conflict error = %v", err)
	}

	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	if plan.State != PlanCompleted || plan.Completion != CompletionRolledBack {
		t.Fatalf("automatic rollback completion = %#v", plan)
	}
}

func TestRolloutPlanRollbackWaitsForEveryInflightNode(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	failure := currentPlanHealth(plan, nodeID(2), false)
	failure.Code = "health_probe_failed"
	plan = mustPlanHealth(t, plan, failure).Plan
	if plan.State != PlanPaused || plan.NodeStates[nodeID(2)] != NodeFailed ||
		plan.NodeStates[nodeID(3)] != NodeDispatched {
		t.Fatalf("partially settled batch = %#v", plan)
	}
	if _, err := ApplyPlanCommand(plan, planCommand(PlanRollback, plan.Revision, "automatic_policy_requested")); !errors.Is(err, ErrPlanBlocked) {
		t.Fatalf("rollback with in-flight node error = %v", err)
	}
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(3), true)).Plan
	if plan.State != PlanRollingBack || len(plan.RollbackBatches) != 2 {
		t.Fatalf("settled automatic rollback = %#v", plan)
	}
}

func TestRolloutPlanPauseSettlesInflightWithoutDispatchingNextBatch(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	plan = mustPlanCommand(t, plan, planCommand(PlanPauseAction, plan.Revision, "maintenance_window")).Plan
	pausedRevision := plan.Revision
	settled := mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true))
	plan = settled.Plan
	if plan.State != PlanPaused || plan.ResumeState != PlanCanary || plan.ActiveBatch != 0 ||
		plan.Revision != pausedRevision+1 || plan.NodeStates[nodeID(1)] != NodeHealthy ||
		plan.NodeStates[nodeID(2)] != NodePending {
		t.Fatalf("settled paused plan = %#v event=%#v", plan, settled.Event)
	}
	plan = mustPlanCommand(t, plan, planCommand(PlanResume, plan.Revision, "maintenance_complete")).Plan
	assertPlanPosition(t, plan, PlanRunning, 1, []string{nodeID(2), nodeID(3)})
}

func TestRolloutPlanRestartPreservesUnknownOutcomeForReconciliation(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	restarted := cloneRolloutPlan(plan)
	if !reflect.DeepEqual(restarted, plan) || restarted.Revision != plan.Revision ||
		restarted.NodeStates[nodeID(1)] != NodeDispatched {
		t.Fatalf("restart changed unresolved snapshot: before=%#v after=%#v", plan, restarted)
	}
	unknown := currentPlanHealth(restarted, nodeID(1), false)
	unknown.Code = "unknown_outcome"
	result := mustPlanHealth(t, restarted, unknown)
	if result.Plan.State != PlanPaused || result.Plan.ResumeState != PlanCanary ||
		result.Plan.NodeStates[nodeID(1)] != NodeDispatched || result.Plan.NodeStates[nodeID(2)] != NodePending ||
		result.Event.Action != "outcome_uncertain" || result.Event.Revision != restarted.Revision+1 {
		t.Fatalf("unknown outcome result = %#v", result)
	}
	if _, err := ApplyPlanCommand(result.Plan, planCommand(PlanRollback, result.Plan.Revision, "automatic_policy_requested")); !errors.Is(err, ErrPlanBlocked) {
		t.Fatalf("rollback with uncertain outcome error = %v", err)
	}
	reconciled := mustPlanHealth(t, result.Plan, currentPlanHealth(result.Plan, nodeID(1), true)).Plan
	if reconciled.State != PlanPaused || reconciled.NodeStates[nodeID(1)] != NodeHealthy {
		t.Fatalf("reconciled outcome = %#v", reconciled)
	}
	reconciled = mustPlanCommand(t, reconciled, planCommand(PlanResume, reconciled.Revision, "outcome_reconciled")).Plan
	if reconciled.State != PlanRunning {
		t.Fatalf("resumed reconciled rollout = %#v", reconciled)
	}
}

func TestRolloutPlanCommandsAreIdempotentAndRevisionGuarded(t *testing.T) {
	plan := mustRolloutPlan(t)
	command := planCommand(PlanStart, plan.Revision, "start_requested")
	first := mustPlanCommand(t, plan, command)
	if _, err := uuid.Parse(first.Event.ID); err != nil || first.Event.Revision != plan.Revision+1 {
		t.Fatalf("event id/revision = %q/%d, parse error = %v", first.Event.ID, first.Event.Revision, err)
	}
	replay, err := ApplyPlanCommand(first.Plan, command)
	if err != nil || !replay.Replayed || replay.Event != first.Event || replay.Plan.Revision != first.Plan.Revision {
		t.Fatalf("command replay = (%#v, %v)", replay, err)
	}
	conflict := command
	conflict.Action = PlanPauseAction
	if _, err := ApplyPlanCommand(first.Plan, conflict); !errors.Is(err, ErrPlanIdempotencyConflict) {
		t.Fatalf("command conflict error = %v", err)
	}
	stale := planCommand(PlanPauseAction, 1, "operator_requested")
	stale.ID = nodeID(999)
	if _, err := ApplyPlanCommand(first.Plan, stale); !errors.Is(err, ErrStalePlanRevision) {
		t.Fatalf("stale command error = %v", err)
	}
}

func TestRolloutPlanExplicitPauseResumeAndRollback(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(2), true)).Plan
	plan = mustPlanCommand(t, plan, planCommand(PlanPauseAction, plan.Revision, "maintenance_window")).Plan
	if plan.State != PlanPaused || plan.ResumeState != PlanRunning {
		t.Fatalf("paused plan = %#v", plan)
	}
	plan = mustPlanCommand(t, plan, planCommand(PlanResume, plan.Revision, "maintenance_complete")).Plan
	if plan.State != PlanRunning {
		t.Fatalf("resumed plan state = %s", plan.State)
	}
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(3), true)).Plan
	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(4), true)).Plan
	if plan.State != PlanCompleted || plan.Completion != CompletionUpgraded {
		t.Fatalf("completed forward rollout = %#v", plan)
	}
	plan = mustPlanCommand(t, plan, planCommand(PlanRollback, plan.Revision, "operator_requested")).Plan
	if plan.State != PlanRollingBack || len(plan.RollbackBatches) != 3 ||
		!reflect.DeepEqual(plan.RollbackBatches[0].NodeIDs, []string{nodeID(4)}) ||
		!reflect.DeepEqual(plan.RollbackBatches[1].NodeIDs, []string{nodeID(2), nodeID(3)}) ||
		!reflect.DeepEqual(plan.RollbackBatches[2].NodeIDs, []string{nodeID(1)}) {
		t.Fatalf("rollback batches = %#v", plan.RollbackBatches)
	}
	for plan.State == PlanRollingBack {
		for _, id := range append([]string(nil), plan.RollbackBatches[plan.ActiveBatch].NodeIDs...) {
			if plan.NodeStates[id] == NodeDispatched {
				plan = mustPlanHealth(t, plan, currentPlanHealth(plan, id, true)).Plan
			}
		}
	}
	if plan.State != PlanCompleted || plan.Completion != CompletionRolledBack {
		t.Fatalf("rollback completion = %#v", plan)
	}
}

func TestRolloutPlanRollbackFailureIsTerminal(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	failure := currentPlanHealth(plan, nodeID(1), false)
	failure.Code = "health_probe_failed"
	plan = mustPlanHealth(t, plan, failure).Plan
	report := currentPlanHealth(plan, nodeID(1), false)
	report.Code = "rollback_health_failed"
	plan = mustPlanHealth(t, plan, report).Plan
	if plan.State != PlanFailed || plan.Completion != CompletionNone {
		t.Fatalf("failed rollback = %#v", plan)
	}
	if _, err := ApplyPlanCommand(plan, planCommand(PlanResume, plan.Revision, "retry_requested")); !errors.Is(err, ErrInvalidPlanTransition) {
		t.Fatalf("resume failed rollback error = %v", err)
	}
}

func TestRolloutPlanRollbackUnknownOutcomeWaitsForReconciliation(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	failure := currentPlanHealth(plan, nodeID(1), false)
	failure.Code = "health_probe_failed"
	plan = mustPlanHealth(t, plan, failure).Plan

	unknown := currentPlanHealth(plan, nodeID(1), false)
	unknown.Code = "unknown_outcome"
	result := mustPlanHealth(t, plan, unknown)
	plan = result.Plan
	if plan.State != PlanRollingBack || plan.NodeStates[nodeID(1)] != NodeDispatched ||
		result.Event.Action != "outcome_uncertain" {
		t.Fatalf("uncertain rollback outcome = %#v event=%#v", plan, result.Event)
	}

	plan = mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	if plan.State != PlanCompleted || plan.Completion != CompletionRolledBack ||
		plan.NodeStates[nodeID(1)] != NodeRolledBack {
		t.Fatalf("reconciled rollback = %#v", plan)
	}
}

func TestCanPlanTransitionIsExhaustive(t *testing.T) {
	states := []PlanState{PlanQueued, PlanCanary, PlanRunning, PlanPaused, PlanRollingBack, PlanCompleted, PlanFailed}
	allowed := map[[2]PlanState]bool{
		{PlanQueued, PlanCanary}: true,
		{PlanCanary, PlanCanary}: true, {PlanCanary, PlanRunning}: true,
		{PlanCanary, PlanPaused}: true, {PlanCanary, PlanRollingBack}: true, {PlanCanary, PlanCompleted}: true,
		{PlanRunning, PlanRunning}: true, {PlanRunning, PlanPaused}: true,
		{PlanRunning, PlanRollingBack}: true, {PlanRunning, PlanCompleted}: true,
		{PlanPaused, PlanCanary}: true, {PlanPaused, PlanRunning}: true,
		{PlanPaused, PlanPaused}: true, {PlanPaused, PlanRollingBack}: true,
		{PlanRollingBack, PlanRollingBack}: true, {PlanRollingBack, PlanCompleted}: true, {PlanRollingBack, PlanFailed}: true,
		{PlanCompleted, PlanRollingBack}: true,
	}
	for _, from := range states {
		for _, to := range states {
			if got := CanPlanTransition(from, to); got != allowed[[2]PlanState{from, to}] {
				t.Fatalf("CanPlanTransition(%q, %q) = %v", from, to, got)
			}
		}
	}
}

func TestRolloutPlanRejectsInvalidTopologyAndReports(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RolloutPlanInput)
	}{
		{"no canary", func(in *RolloutPlanInput) { in.Groups[0].Canary = false }},
		{"two canaries", func(in *RolloutPlanInput) { in.Groups[1].Canary = true }},
		{"duplicate node", func(in *RolloutPlanInput) { in.Groups[1].Targets[0].NodeID = nodeID(1) }},
		{"empty group", func(in *RolloutPlanInput) { in.Groups[0].Targets = nil }},
		{"oversized batch", func(in *RolloutPlanInput) { in.Groups[0].BatchSize = 2 }},
		{"invalid version", func(in *RolloutPlanInput) { in.TargetVersion = "v2" }},
		{"missing release sequence", func(in *RolloutPlanInput) { in.ReleaseSequence = 0 }},
		{"invalid grant digest", func(in *RolloutPlanInput) { in.GrantDigest = "invalid" }},
		{"automatic rollback disabled", func(in *RolloutPlanInput) { in.AutomaticRollback = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validRolloutPlanInput()
			test.edit(&input)
			if _, err := NewRolloutPlan(input); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("NewRolloutPlan() error = %v", err)
			}
		})
	}

	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	wrongNode := currentPlanHealth(plan, nodeID(4), true)
	wrongNode.DispatchRevision = plan.Revision
	if _, err := ApplyPlanHealth(plan, wrongNode); !errors.Is(err, ErrPlanNodeNotActive) {
		t.Fatalf("inactive node error = %v", err)
	}
	badFailure := currentPlanHealth(plan, nodeID(1), false)
	if _, err := ApplyPlanHealth(plan, badFailure); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("missing failure code error = %v", err)
	}
}

func TestRolloutPlanRejectsCorruptedPersistedSnapshot(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan.SchemaVersion = 0
	if _, err := ApplyPlanCommand(plan, planCommand(PlanStart, plan.Revision, "start_requested")); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("corrupted schema version error = %v", err)
	}

	plan = mustRolloutPlan(t)
	plan.AutomaticRollback = false
	if _, err := ApplyPlanCommand(plan, planCommand(PlanStart, plan.Revision, "start_requested")); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("corrupted rollback policy error = %v", err)
	}

	plan = mustRolloutPlan(t)
	plan.Blockers = append(plan.Blockers, PlanBlocker{Code: BlockerIrreversibleMigration})
	if _, err := ApplyPlanCommand(plan, planCommand(PlanStart, plan.Revision, "start_requested")); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("corrupted blocker error = %v", err)
	}

	plan = mustRolloutPlan(t)
	plan.Batches[0].NodeIDs[0] = nodeID(99)
	if _, err := ApplyPlanCommand(plan, planCommand(PlanStart, plan.Revision, "start_requested")); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("corrupted batch error = %v", err)
	}

	plan = mustRolloutPlan(t)
	plan.Revision++
	if _, err := ApplyPlanCommand(plan, planCommand(PlanStart, plan.Revision, "start_requested")); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("corrupted receipt revision error = %v", err)
	}
}

func TestRolloutPlanRejectsCorruptedReceiptStateChain(t *testing.T) {
	running := func() RolloutPlan {
		plan := mustRolloutPlan(t)
		plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
		return mustPlanHealth(t, plan, currentPlanHealth(plan, nodeID(1), true)).Plan
	}
	tests := []struct {
		name   string
		mutate func(*RolloutPlan)
	}{
		{name: "from does not continue prior revision", mutate: func(plan *RolloutPlan) {
			plan.HealthReceipts[0].Event.From = PlanRunning
		}},
		{name: "final event does not match aggregate", mutate: func(plan *RolloutPlan) {
			plan.HealthReceipts[0].Event.To = PlanCanary
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := running()
			test.mutate(&plan)
			_, err := ApplyPlanCommand(plan, planCommand(PlanPauseAction, plan.Revision, "maintenance_window"))
			if !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("ApplyPlanCommand() error = %v, want invalid persisted state chain", err)
			}
		})
	}
}

func TestRolloutPlanRejectsImpossiblePersistedProgress(t *testing.T) {
	running := func() RolloutPlan {
		plan := mustRolloutPlan(t)
		plan.State = PlanRunning
		plan.ActiveBatch = 1
		plan.NodeStates[nodeID(1)] = NodeHealthy
		plan.NodeStates[nodeID(2)] = NodeDispatched
		plan.NodeStates[nodeID(3)] = NodeDispatched
		return plan
	}
	rollback := func() RolloutPlan {
		plan := mustRolloutPlan(t)
		plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
		failure := currentPlanHealth(plan, nodeID(1), false)
		failure.Code = "health_probe_failed"
		return mustPlanHealth(t, plan, failure).Plan
	}
	tests := []struct {
		name string
		plan func() RolloutPlan
	}{
		{"running prior batch not healthy", func() RolloutPlan {
			plan := running()
			plan.NodeStates[nodeID(1)] = NodeDispatched
			return plan
		}},
		{"running current batch pending", func() RolloutPlan {
			plan := running()
			plan.NodeStates[nodeID(2)] = NodePending
			return plan
		}},
		{"running current batch already complete", func() RolloutPlan {
			plan := running()
			plan.NodeStates[nodeID(2)] = NodeHealthy
			plan.NodeStates[nodeID(3)] = NodeHealthy
			return plan
		}},
		{"running future batch advanced", func() RolloutPlan {
			plan := running()
			plan.NodeStates[nodeID(4)] = NodeHealthy
			return plan
		}},
		{"running retains resume state", func() RolloutPlan {
			plan := running()
			plan.ResumeState = PlanRunning
			return plan
		}},
		{"completed upgraded with pending node", func() RolloutPlan {
			plan := running()
			plan.State = PlanCompleted
			plan.Completion = CompletionUpgraded
			plan.ActiveBatch = -1
			plan.NodeStates[nodeID(2)] = NodeHealthy
			plan.NodeStates[nodeID(3)] = NodeHealthy
			return plan
		}},
		{"rolling back skips unfinished prior rollback batch", func() RolloutPlan {
			plan := rollback()
			plan.ActiveBatch = 1
			return plan
		}},
		{"rolling back future batch already rolled back", func() RolloutPlan {
			plan := rollback()
			plan.NodeStates[nodeID(1)] = NodeRolledBack
			return plan
		}},
		{"completed rollback without rolled back nodes", func() RolloutPlan {
			plan := rollback()
			plan.State = PlanCompleted
			plan.Completion = CompletionRolledBack
			plan.ActiveBatch = -1
			return plan
		}},
		{"failed rollback without failure", func() RolloutPlan {
			plan := rollback()
			plan.State = PlanFailed
			return plan
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if plan := test.plan(); validRolloutPlan(plan) {
				t.Fatalf("validRolloutPlan() accepted impossible snapshot: %#v", plan)
			}
		})
	}
}

func TestRolloutPlanBatchPartitionProperty(t *testing.T) {
	for targetCount := 1; targetCount <= 32; targetCount++ {
		for batchSize := 1; batchSize <= targetCount; batchSize++ {
			input := validRolloutPlanInput()
			input.Groups[1].BatchSize = batchSize
			input.Groups[1].Targets = make([]PlanTarget, targetCount)
			for index := range input.Groups[1].Targets {
				input.Groups[1].Targets[index] = PlanTarget{
					NodeID: nodeID(index + 1000), AgentVersion: "1.5.0", ProtocolVersion: 2,
				}
			}
			plan, err := NewRolloutPlan(input)
			if err != nil {
				t.Fatalf("targets=%d batch=%d: %v", targetCount, batchSize, err)
			}
			var flattened []string
			for _, batch := range plan.Batches[1:] {
				if batch.Canary || len(batch.NodeIDs) == 0 || len(batch.NodeIDs) > batchSize {
					t.Fatalf("targets=%d batch=%d: %#v", targetCount, batchSize, batch)
				}
				flattened = append(flattened, batch.NodeIDs...)
			}
			want := make([]string, targetCount)
			for index := range want {
				want[index] = nodeID(index + 1000)
			}
			if !reflect.DeepEqual(flattened, want) {
				t.Fatalf("targets=%d batch=%d flattened=%v", targetCount, batchSize, flattened)
			}
		}
	}
}

func validRolloutPlanInput() RolloutPlanInput {
	profile := CommandProfile{
		Platform: "linux", Architecture: "amd64",
		Compatibility: entitlement.UpgradeExecutionCompatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: entitlement.UpgradeExecutionHealthPolicy{Command: []string{"{artifact}", "--version"},
			ActivationTimeoutNanoseconds: int64(30 * time.Second), ObservationWindowNanoseconds: int64(time.Minute),
			IntervalNanoseconds: int64(time.Second), ProbeTimeoutNanoseconds: int64(time.Second),
			RequiredConsecutiveSuccesses: 3},
		Rollout:  entitlement.UpgradeExecutionRolloutPolicy{Percentage: 100},
		Rollback: entitlement.UpgradeExecutionRollbackPolicy{Automatic: true},
	}
	input := RolloutPlanInput{
		ID: nodeID(100), ParentGrantID: nodeID(99), GrantDigest: planDigest(0x41),
		ParentGrantExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), ReleaseSequence: 7,
		ArtifactBundleID: nodeID(98), ArtifactBundleSHA256: planDigest(0x45),
		CommandIssuanceNotAfter: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC).Unix(),
		Component:               "edge-agent", ArtifactID: nodeID(101), SHA256Digest: planDigest(0x42), ArtifactSizeBytes: 4096,
		CurrentVersion: "1.0.0", TargetVersion: "2.0.0",
		AutomaticRollback: true, ForwardProfile: profile, RollbackProfile: profile,
		Safety: PlanSafety{
			MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0",
			ProtocolMin: 2, ProtocolMax: 3, RollbackAvailable: true,
		},
		Groups: []PlanGroup{
			{ID: "canary", Canary: true, BatchSize: 1, Targets: []PlanTarget{
				{NodeID: nodeID(1), AgentVersion: "1.5.0", ProtocolVersion: 2},
			}},
			{ID: "primary", BatchSize: 2, Targets: []PlanTarget{
				{NodeID: nodeID(2), AgentVersion: "1.5.0", ProtocolVersion: 2},
				{NodeID: nodeID(3), AgentVersion: "2.0.0", ProtocolVersion: 3},
				{NodeID: nodeID(4), AgentVersion: "1.0.0", ProtocolVersion: 2},
			}},
		},
	}
	for name, value := range map[string]any{
		"RollbackGrantDigest":       planDigest(0x41),
		"RollbackReleaseSequence":   uint64(7),
		"RollbackArtifactID":        nodeID(102),
		"RollbackSHA256Digest":      planDigest(0x44),
		"RollbackArtifactSizeBytes": int64(2048),
	} {
		field := reflect.ValueOf(&input).Elem().FieldByName(name)
		if field.IsValid() {
			field.Set(reflect.ValueOf(value))
		}
	}
	return input
}

func mustRolloutPlan(t *testing.T) RolloutPlan {
	t.Helper()
	plan, err := NewRolloutPlan(validRolloutPlanInput())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func planCommand(action PlanAction, revision uint64, reason string) PlanCommand {
	return PlanCommand{ID: nodeID(int(revision) + 200), Action: action, ExpectedRevision: revision, Reason: reason}
}

func planHealth(node string, success bool, revision uint64) PlanHealthEvent {
	return PlanHealthEvent{ID: nodeID(int(revision) + 300), NodeID: node, Success: success, DispatchRevision: revision}
}

func currentPlanHealth(plan RolloutPlan, node string, success bool) PlanHealthEvent {
	health := planHealth(node, success, plan.NodeDispatchRevisions[node])
	health.ID = nodeID(int(plan.Revision) + 300)
	if success {
		health.InstallerTransactionID = "txn-plan-health"
		activeArtifact, lastKnownGoodArtifact := plan.SHA256Digest, plan.RollbackSHA256Digest
		if plan.State == PlanRollingBack {
			activeArtifact, lastKnownGoodArtifact = lastKnownGoodArtifact, activeArtifact
		}
		health.ActiveEvidence = &ActiveProbeEvidence{Schema: ActiveProbeEvidenceSchema,
			ActiveArtifactSHA256: activeArtifact, ActiveConfigSHA256: planDigest(0x70),
			LastKnownGoodArtifactSHA256: lastKnownGoodArtifact,
			LastKnownGoodConfigSHA256:   planDigest(0x71),
			ProbeObservedAt:             time.Date(2026, 8, 6, 2, 0, 0, 0, time.UTC),
			ProbeDeadline:               time.Date(2026, 8, 6, 2, 1, 0, 0, time.UTC)}
		health.ActiveEvidence.EvidenceSHA256 =
			activeProbeEvidenceDigest(health.InstallerTransactionID, *health.ActiveEvidence)
	}
	return health
}

func mustPlanCommand(t *testing.T, plan RolloutPlan, command PlanCommand) PlanApplyResult {
	t.Helper()
	result, err := ApplyPlanCommand(plan, command)
	if err != nil {
		t.Fatalf("ApplyPlanCommand(%s) error = %v", command.Action, err)
	}
	return result
}

func mustPlanHealth(t *testing.T, plan RolloutPlan, event PlanHealthEvent) PlanApplyResult {
	t.Helper()
	result, err := ApplyPlanHealth(plan, event)
	if err != nil {
		t.Fatalf("ApplyPlanHealth(%s) error = %v", event.NodeID, err)
	}
	return result
}

func assertPlanPosition(t *testing.T, plan RolloutPlan, state PlanState, batch int, nodes []string) {
	t.Helper()
	if plan.State != state || plan.ActiveBatch != batch {
		t.Fatalf("plan position state=%s batch=%d", plan.State, plan.ActiveBatch)
	}
	for _, id := range nodes {
		if plan.NodeStates[id] != NodeDispatched {
			t.Fatalf("node %s state = %s", id, plan.NodeStates[id])
		}
	}
}

func hasPlanBlocker(plan RolloutPlan, code PlanBlockerCode) bool {
	for _, blocker := range plan.Blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func nodeID(value int) string {
	return "00000000-0000-4000-8000-" + leftPad12(value)
}

func planDigest(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func leftPad12(value int) string {
	const digits = "000000000000"
	text := []byte(digits)
	for index := len(text) - 1; value > 0; index-- {
		text[index] = byte('0' + value%10)
		value /= 10
	}
	return string(text)
}
