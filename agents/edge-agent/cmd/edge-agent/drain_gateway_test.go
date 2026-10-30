package main

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/drainruntime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestDrainCapabilityIsExplicitlyAddedOnlyForReadyRuntime(t *testing.T) {
	capabilities := agentCapabilitiesWithFirewall("1.27.1", false)
	if hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL) {
		t.Fatal("drain capability was advertised without a runtime")
	}
	capabilities.Features = append(capabilities.Features, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL, ApiVersion: 1,
	})
	if !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL) {
		t.Fatal("ready drain runtime capability was not advertised")
	}
}

func TestFormalDrainObservationFailureRemainsRecoverable(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute)
	compiled := drainruntime.CompiledPlan{
		Plan:   drainruntime.Plan{PlanID: "deploy-v2", Revision: 2},
		Digest: "observation-digest",
	}
	result := deployment.DrainResult{
		DeploymentID: "deploy-v2", Revision: 2, Digest: compiled.Digest,
		Phase: deployment.DrainPhaseDrainingOld, StartedAt: now, Deadline: deadline,
		RemainingOldWorkers: 3,
		Transitions: []deployment.DrainTransition{
			{Sequence: 1, Phase: deployment.DrainPhaseHealthGate, At: now},
			{Sequence: 2, Phase: deployment.DrainPhaseDrainingOld, At: now},
		},
	}

	mapped, err := mapFormalDrainResult(compiled, result, errors.New("temporary procfs read failure"), now)
	if !errors.Is(err, drainruntime.ErrDrainObservationFailed) || mapped.Phase != drainruntime.PhaseDrainingOld ||
		mapped.RemainingOldWorkers != 3 || !mapped.DrainDeadline.Equal(deadline) {
		t.Fatalf("observation failure mapping = (%+v, %v)", mapped, err)
	}

	handler := &formalDrainHandler{}
	handler.updateSnapshot(mapped, err)
	if snapshot := handler.Snapshot(); !snapshot.Pending || !snapshot.Degraded ||
		snapshot.Phase != drainruntime.PhaseDrainingOld || snapshot.LastErrorCode != "DRAIN_OBSERVATION_FAILED" {
		t.Fatalf("observation failure snapshot = %+v", snapshot)
	}

	for _, terminal := range []error{deployment.ErrConflict, deployment.ErrCorruptState, deployment.ErrDrainDeadline} {
		_, mappedErr := mapFormalDrainResult(compiled, result, terminal, now)
		if errors.Is(mappedErr, drainruntime.ErrDrainObservationFailed) {
			t.Fatalf("terminal error %v was classified as recoverable", terminal)
		}
	}
}
