package gatewayclient

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestOPS09ExplicitRollbackCarriesExactActiveIdentity(t *testing.T) {
	client, manager, first, firstWire, _, privateKey := activeIdentityClient(t)
	firstRecord := persistActiveIdentityCommand(t, client, first, firstWire)
	completeDeploymentWithoutAck(t, client, manager, firstRecord)

	second, secondWire := nextActiveIdentityDeployment(t, first, privateKey)
	secondBundle, err := decodeConfigurationBundle(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: second.DeploymentId, Attempt: second.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: second.ConfigVersionId, PreviousVersionID: first.ConfigVersionId, Bundle: secondBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(second) = (%+v, %v)", result, err)
	}
	secondRecord := persistActiveIdentityCommand(t, client, second, secondWire)
	completeDeploymentWithoutAck(t, client, manager, secondRecord)

	rollback := proto.Clone(second).(*agentv1.DeploymentCommand)
	rollback.Event.EventId = uuid.NewString()
	rollback.Event.RequestId = uuid.NewString()
	rollback.DeploymentId = uuid.NewString()
	rollback.RolloutId = uuid.NewString()
	rollback.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	rollback.ConfigVersionId = first.ConfigVersionId
	rollback.PreviousConfigVersionId = proto.String(second.ConfigVersionId)
	rollback.Artifacts = nil
	rollbackRecord, _, err := client.store.putCommand(rollback, deliveredStatus(rollback))
	if err != nil {
		t.Fatal(err)
	}
	result, err = manager.Process(context.Background(), deployment.Command{
		DeploymentID: rollback.DeploymentId, Attempt: rollback.Attempt, Action: deployment.ActionRollback,
		ConfigVersionID: rollback.ConfigVersionId, PreviousVersionID: rollback.GetPreviousConfigVersionId(),
	})
	if err != nil || result.State != deployment.StateReverted {
		t.Fatalf("Process(rollback) = (%+v, %v)", result, err)
	}
	if err := client.completeDeploymentRecord(rollbackRecord.RecordKey, statusesForResult(rollback, result), true); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(rollbackRecord.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(persisted)
	if err != nil || len(statuses) == 0 {
		t.Fatalf("statusesFromRecord() = (%d, %v)", len(statuses), err)
	}
	final := statuses[len(statuses)-1]
	assertActiveIdentity(t, final.ActiveConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
	assertActiveProbeCheckOPS09(t, final)
	forSession := deploymentStatusForSession(final, true)
	assertActiveIdentity(t, forSession.ActiveConfigIdentity, first.ConfigVersionId, first.Artifacts[0].Sha256)
}

func assertActiveProbeCheckOPS09(t *testing.T, status *agentv1.DeploymentStatus) {
	t.Helper()
	for _, check := range status.GetChecks() {
		if check.GetName() == "edge_active_config_probe" && check.GetSucceeded() &&
			check.GetSummary() == "active config runtime probe passed" && check.GetLatencyDuration() != nil &&
			check.GetLatencyDuration().CheckValid() == nil && check.GetLatencyDuration().AsDuration() >= 0 {
			return
		}
	}
	t.Fatalf("terminal status has no exact active probe evidence: %+v", status.GetChecks())
}

func TestOPS09StatusesForResultCarryProbeForApplyAndRollback(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now),
			CorrelationId: uuid.NewString(),
		},
		DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: uuid.NewString(),
	}
	for _, test := range []struct {
		name   string
		action deployment.Action
		state  deployment.State
	}{
		{name: "apply", action: deployment.ActionApply, state: deployment.StateHealthy},
		{name: "rollback", action: deployment.ActionRollback, state: deployment.StateReverted},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := deployment.Result{
				DeploymentID: command.DeploymentId, Attempt: command.Attempt, Action: test.action,
				ConfigVersionID: command.ConfigVersionId, State: test.state, Sequence: 2,
				Transitions: []deployment.Transition{
					{Sequence: 1, State: deployment.StateDelivered, At: now},
					{Sequence: 2, State: test.state, At: now.Add(time.Second)},
				},
			}
			statuses := statusesForResult(command, result)
			if len(statuses) != 1 {
				t.Fatalf("statuses = %d, want 1", len(statuses))
			}
			assertActiveProbeCheckOPS09(t, statuses[0])
		})
	}
}
