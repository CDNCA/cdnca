package gatewayclient

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// activatedError stands in for dynroute.MaintenanceError (gatewayclient
// does not import dynroute).
type activatedError struct{ step string }

func (e activatedError) Error() string {
	return "generation 9 active, post-activation " + e.step + " failed: disk full"
}
func (activatedError) ActivatedMaintenanceFailure() bool { return true }

// E1 (PJ-E02): an error after activation is not "running config
// unchanged": the journal is the success one plus a failed maintenance check.
func TestDynamicRoutingResultReportsActivatedMaintenanceFailure(t *testing.T) {
	started := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	now := started.Add(time.Second)
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{EventId: "0d13c000-0000-4000-8000-0000000000e1", RequestId: "0d13c000-0000-4000-8000-0000000000e2",
			OccurredTime: timestamppb.New(started)},
		DeploymentId: "0d13c000-0000-4000-8000-0000000000e3", Attempt: 1, ConfigVersionId: "0d13c000-0000-4000-8000-0000000000e4",
	}
	for _, step := range []string{"save_state", "retain"} {
		for _, action := range []deployment.Action{deployment.ActionApply, deployment.ActionRollback} {
			err := fmt.Errorf("wrapped: %w", activatedError{step: step})
			if !DynamicRoutingActivated(err) {
				t.Fatalf("%s: not recognised as activated", step)
			}
			result := DynamicRoutingResult(command.DeploymentId, 1, action, command.ConfigVersionId, started, now, err)
			want := deployment.StateHealthy
			if action == deployment.ActionRollback {
				want = deployment.StateReverted
			}
			if result.State != want || result.RunningConfigUnchanged || result.ErrorCode != "" || len(result.Transitions) != 5 {
				t.Fatalf("%s %s: result %+v", step, action, result)
			}
			if latest := result.Transitions[4]; latest.MaintenanceFailure == "" || latest.RunningConfigUnchanged {
				t.Fatalf("%s %s: latest %+v", step, action, latest)
			}
			statuses := statusesForResult(command, result)
			terminal := statuses[len(statuses)-1]
			if terminal.RunningConfigUnchanged || terminal.Error != nil {
				t.Fatalf("%s %s: terminal %+v", step, action, terminal)
			}
			var found *agentv1.CheckResult
			for _, check := range terminal.Checks {
				if check.Name == PostActivationMaintenanceCheckName {
					found = check
				}
			}
			if found == nil || found.Succeeded || found.Summary == "" {
				t.Fatalf("%s %s: checks %+v", step, action, terminal.Checks)
			}
		}
	}

	// Activated, failed health, compensated
	result := DynamicRoutingResult(command.DeploymentId, 1, deployment.ActionApply, command.ConfigVersionId, started, now,
		fmt.Errorf("apply: %w", revertedError{}))
	wantStates := []deployment.State{deployment.StateDelivered, deployment.StateStaged, deployment.StatePrechecked,
		deployment.StateActivated, deployment.StateReverting, deployment.StateReverted}
	assertStates(t, "reverted", result, wantStates)
	if result.State != deployment.StateReverted || result.RunningConfigUnchanged || result.Transitions[4].ErrorCode != "HEALTH_FAILED" ||
		!strings.Contains(result.Summary, "reverted to generation 1") {
		t.Fatalf("reverted result %+v", result)
	}
	terminal := statusesForResult(command, result)
	if last := terminal[len(terminal)-1]; last.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED ||
		last.RunningConfigUnchanged || last.Error != nil {
		t.Fatalf("reverted terminal %+v", last)
	}
	// activated, failed health, compensation failed: uncertain, never unchanged
	result = DynamicRoutingResult(command.DeploymentId, 1, deployment.ActionApply, command.ConfigVersionId, started, now,
		fmt.Errorf("apply: %w", rollbackFailedError{}))
	wantStates[5] = deployment.StateRollbackFailed
	assertStates(t, "rollback_failed", result, wantStates)
	if result.RunningConfigUnchanged || result.ErrorCode != "ROLLBACK_RESTORE_FAILED" ||
		!strings.Contains(result.Summary, "unhealthy") || !strings.Contains(result.Summary, "rollback") {
		t.Fatalf("rollback_failed result %+v", result)
	}
	terminal = statusesForResult(command, result)
	if last := terminal[len(terminal)-1]; last.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED ||
		last.RunningConfigUnchanged || last.Error == nil {
		t.Fatalf("rollback_failed terminal %+v", last)
	}

	// an error before activation still reports the running config unchanged
	result = DynamicRoutingResult(command.DeploymentId, 1, deployment.ActionApply, command.ConfigVersionId, started, now,
		errors.New("site index generation 9 unhealthy"))
	if result.State != deployment.StateFailed || !result.RunningConfigUnchanged || result.Transitions[2].MaintenanceFailure != "" {
		t.Fatalf("result %+v", result)
	}
	// success: no maintenance check
	result = DynamicRoutingResult(command.DeploymentId, 1, deployment.ActionApply, command.ConfigVersionId, started, now, nil)
	for _, status := range statusesForResult(command, result) {
		for _, check := range status.Checks {
			if check.Name == PostActivationMaintenanceCheckName {
				t.Fatalf("maintenance check on success: %+v", status)
			}
		}
	}
}

// revertedError / rollbackFailedError stand in for dynroute.RevertedError
// and dynroute.RollbackFailedError.
type revertedError struct{}

func (revertedError) Error() string {
	return "generation 2 activated and failed: site index generation 2 unhealthy: probe 503; reverted to generation 1"
}
func (revertedError) RevertedAfterActivation() bool { return true }

type rollbackFailedError struct{}

func (rollbackFailedError) Error() string {
	return "generation 2 activated and failed: site index generation 2 unhealthy: probe 503; rollback to the previous generation failed: site index control POST /rollback: 500"
}
func (rollbackFailedError) RollbackFailedAfterActivation() bool { return true }

func assertStates(t *testing.T, name string, result deployment.Result, want []deployment.State) {
	t.Helper()
	if len(result.Transitions) != len(want) {
		t.Fatalf("%s: transitions %+v", name, result.Transitions)
	}
	for index, transition := range result.Transitions {
		if transition.State != want[index] || transition.Sequence != uint64(index+1) || transition.RunningConfigUnchanged {
			t.Fatalf("%s: transition %d %+v, want %s", name, index, transition, want[index])
		}
	}
}
