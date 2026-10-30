package controlupgrade

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStateStringAloneCannotAdvanceCanary(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	health := currentPlanHealth(plan, nodeID(1), true)
	health.InstallerTransactionID = ""
	health.ActiveEvidence = nil
	if _, err := ApplyPlanHealth(plan, health); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("state-only health error = %v", err)
	}
	if plan.State != PlanCanary || plan.NodeStates[nodeID(1)] != NodeDispatched {
		t.Fatalf("state-only health mutated plan = %#v", plan)
	}
}

func TestStatusV2EvidenceBindsForwardAndRollbackHashes(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	command := RolloutNodeCommand{PlanRevision: plan.NodeDispatchRevisions[nodeID(1)], Action: "upgrade"}
	receipt := RolloutStatusReceipt{Schema: EdgeUpgradeStatusSchemaV2, StatusID: nodeID(710),
		PlanID: plan.ID, NodeID: nodeID(1), State: "healthy", ObservedAt: time.Now().UTC()}
	payload := rolloutStatusPayload{
		Schema: EdgeUpgradeStatusSchemaV2, InstallerTransactionID: "txn-control-active-probe",
		ActiveEvidence: activeProbeEvidenceForPlan(plan, false, receipt.ObservedAt),
	}
	health, err := rolloutHealthFromStatus(command, receipt, payload)
	if err != nil || !health.Success || health.ActiveEvidence == nil {
		t.Fatalf("v2 health = (%#v, %v)", health, err)
	}
	result, err := ApplyPlanHealth(plan, health)
	if err != nil || result.Plan.State != PlanRunning {
		t.Fatalf("v2 canary result = (%#v, %v)", result, err)
	}

	for name, mutate := range map[string]func(*rolloutStatusPayload){
		"artifact": func(value *rolloutStatusPayload) {
			value.ActiveEvidence.ActiveArtifactSHA256 = plan.RollbackSHA256Digest
		},
		"config": func(value *rolloutStatusPayload) { value.ActiveEvidence.ActiveConfigSHA256 = planDigest(0x72) },
		"deadline": func(value *rolloutStatusPayload) {
			value.ActiveEvidence.ProbeDeadline = value.ActiveEvidence.ProbeObservedAt.Add(-time.Second)
		},
		"digest": func(value *rolloutStatusPayload) { value.ActiveEvidence.EvidenceSHA256 = planDigest(0x73) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := payload
			candidate.ActiveEvidence = cloneControlActiveProbeEvidence(payload.ActiveEvidence)
			mutate(&candidate)
			if _, err := rolloutHealthFromStatus(command, receipt, candidate); !errors.Is(err, ErrInvalidPlanEvent) {
				t.Fatalf("tampered %s error = %v", name, err)
			}
		})
	}

	rollbackReceipt := receipt
	rollbackReceipt.State = "rolled_back"
	rollbackPayload := payload
	rollbackPayload.ActiveEvidence = activeProbeEvidenceForPlan(plan, true, receipt.ObservedAt)
	rollbackCommand := command
	rollbackCommand.Action = "rollback"
	rollbackHealth, err := rolloutHealthFromStatus(rollbackCommand, rollbackReceipt, rollbackPayload)
	if err != nil || !rollbackHealth.Success || rollbackHealth.ActiveEvidence.ActiveArtifactSHA256 != plan.RollbackSHA256Digest ||
		rollbackHealth.ActiveEvidence.LastKnownGoodArtifactSHA256 != plan.SHA256Digest {
		t.Fatalf("rollback health = (%#v, %v)", rollbackHealth, err)
	}
}

func TestV1TerminalStatusIsStaleAndNeverBecomesHealth(t *testing.T) {
	receipt := RolloutStatusReceipt{Schema: EdgeUpgradeStatusSchemaV1, StatusID: nodeID(720),
		PlanID: nodeID(721), NodeID: nodeID(722), State: "healthy", ObservedAt: time.Now().UTC()}
	payload := rolloutStatusPayload{Schema: EdgeUpgradeStatusSchemaV1, InstallerTransactionID: "txn-legacy-v1"}
	if _, err := rolloutHealthFromStatus(RolloutNodeCommand{PlanRevision: 9, Action: "upgrade"}, receipt, payload); !errors.Is(err, ErrStaleStatusEvidence) {
		t.Fatalf("legacy terminal error = %v", err)
	}
}

func TestStatusV2AllowsReceiptAfterCompletedProbeWindow(t *testing.T) {
	probeObserved := time.Date(2026, 8, 6, 2, 0, 0, 0, time.UTC)
	deadline := probeObserved.Add(time.Second)
	statusObserved := deadline.Add(time.Second)
	evidence := &ActiveProbeEvidence{
		Schema:               ActiveProbeEvidenceSchema,
		ActiveArtifactSHA256: strings.Repeat("a", 64), ActiveConfigSHA256: strings.Repeat("b", 64),
		LastKnownGoodArtifactSHA256: strings.Repeat("c", 64),
		LastKnownGoodConfigSHA256:   strings.Repeat("d", 64),
		ProbeObservedAt:             probeObserved, ProbeDeadline: deadline,
	}
	evidence.EvidenceSHA256 = activeProbeEvidenceDigest("txn-control-window-complete", *evidence)
	payload := rolloutStatusPayload{
		Schema: EdgeUpgradeStatusSchemaV2, StatusID: nodeID(730), StatusRevision: 4,
		CommandID: nodeID(731), PlanID: nodeID(732), PlanRevision: 2,
		InstallationID: nodeID(733), NodeID: nodeID(734), CommandSHA256: strings.Repeat("e", 64),
		State: "healthy", CurrentVersion: "2.0.0", PreviousVersion: "1.0.0",
		InstallerTransactionID: "txn-control-window-complete", ObservedAt: statusObserved,
		ActiveEvidence: evidence,
	}
	wire, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RolloutStatusReceipt{
		Schema: payload.Schema, StatusID: payload.StatusID, StatusRevision: payload.StatusRevision,
		CommandID: payload.CommandID, PlanID: payload.PlanID, PlanRevision: payload.PlanRevision,
		InstallationID: payload.InstallationID, NodeID: payload.NodeID, CommandSHA256: payload.CommandSHA256,
		StatusBytes: wire, StatusSHA256: rolloutWireDigest(wire), State: payload.State, ObservedAt: payload.ObservedAt,
	}
	if !validRolloutStatusPayload(receipt) {
		t.Fatal("completed probe window status rejected by payload validation")
	}
	if health, err := rolloutHealthFromStatus(RolloutNodeCommand{PlanRevision: 2}, receipt, payload); err != nil || !health.Success {
		t.Fatalf("completed probe window health = (%#v, %v)", health, err)
	}
}

func activeProbeEvidenceForPlan(plan RolloutPlan, rollback bool, observed time.Time) *ActiveProbeEvidence {
	activeArtifact, lkgArtifact := plan.SHA256Digest, plan.RollbackSHA256Digest
	if rollback {
		activeArtifact, lkgArtifact = lkgArtifact, activeArtifact
	}
	result := &ActiveProbeEvidence{
		Schema:               ActiveProbeEvidenceSchema,
		ActiveArtifactSHA256: activeArtifact, ActiveConfigSHA256: planDigest(0x70),
		LastKnownGoodArtifactSHA256: lkgArtifact, LastKnownGoodConfigSHA256: planDigest(0x71),
		ProbeObservedAt: observed.Add(-time.Second), ProbeDeadline: observed.Add(time.Second),
	}
	result.EvidenceSHA256 = activeProbeEvidenceDigest("txn-control-active-probe", *result)
	return result
}

// An upgrade command that ends rolled_back means the agent restored the
// previous artifact (edge-agent updater: active=baseline, last known good=the
// failed forward artifact; migration 105 enforces the same direction). The
// plan must count it as a failed upgrade, not as a healthy forward node.
func TestUpgradeRolledBackStatusCountsAsFailedUpgrade(t *testing.T) {
	plan := mustRolloutPlan(t)
	plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	command := RolloutNodeCommand{PlanRevision: plan.NodeDispatchRevisions[nodeID(1)], Action: "upgrade"}
	receipt := RolloutStatusReceipt{Schema: EdgeUpgradeStatusSchemaV2, StatusID: nodeID(730),
		PlanID: plan.ID, NodeID: nodeID(1), State: "rolled_back", ObservedAt: time.Now().UTC()}
	payload := rolloutStatusPayload{Schema: EdgeUpgradeStatusSchemaV2, ErrorCode: "HEALTH.PROBE-FAILED",
		InstallerTransactionID: "txn-control-active-probe",
		ActiveEvidence:         activeProbeEvidenceForPlan(plan, true, receipt.ObservedAt)}
	health, err := rolloutHealthFromStatus(command, receipt, payload)
	if err != nil || health.Success || health.Code != "health_probe_failed" || health.ActiveEvidence != nil {
		t.Fatalf("upgrade rolled_back health = (%#v, %v)", health, err)
	}
	// Same as a failed upgrade: the plan pauses, or with automatic rollback
	// (mustRolloutPlan) begins rolling back; it never counts the node healthy.
	result, err := ApplyPlanHealth(plan, health)
	if err != nil || result.Event.Action != "health_failed" || result.Event.Reason != "health_probe_failed" ||
		result.Plan.NodeStates[nodeID(1)] == NodeHealthy ||
		result.Plan.State != PlanPaused && result.Plan.State != PlanRollingBack {
		t.Fatalf("upgrade rolled_back plan = (%s %s %#v, %v)", result.Plan.State, result.Plan.NodeStates[nodeID(1)], result.Event, err)
	}
	payload.ActiveEvidence = nil
	if _, err := rolloutHealthFromStatus(command, receipt, payload); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("upgrade rolled_back without evidence = %v", err)
	}
}
