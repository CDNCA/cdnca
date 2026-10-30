package edgedeployment

import (
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

// fix-stoppolicy2: a frozen node (expired service ticket) refuses an APPLY
// with FAILED_PRECONDITION "installation_frozen: ...", running config
// unchanged (agent gatewayclient). Only that is a frozen refusal.
func TestFrozenRefusalOnlyForFrozenApply(t *testing.T) {
	frozen := func(mutate func(*agentv1.DeploymentStatus)) *agentv1.DeploymentStatus {
		status := &agentv1.DeploymentStatus{
			State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, RunningConfigUnchanged: true,
			Error: &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, Retryable: true,
				Message: "installation_frozen: the node service ticket expired; new publications wait for a renewed ticket"},
		}
		if mutate != nil {
			mutate(status)
		}
		return status
	}
	for _, tc := range []struct {
		name   string
		action string
		status *agentv1.DeploymentStatus
		want   bool
	}{
		{"frozen apply", "apply", frozen(nil), true},
		{"rollback is never frozen", "rollback", frozen(nil), false},
		{"other precondition", "apply", frozen(func(s *agentv1.DeploymentStatus) { s.Error.Message = "capability missing" }), false},
		{"other code", "apply", frozen(func(s *agentv1.DeploymentStatus) { s.Error.Code = commonv1.ErrorCode_ERROR_CODE_INTERNAL }), false},
		{"changed running config", "apply", frozen(func(s *agentv1.DeploymentStatus) { s.RunningConfigUnchanged = false }), false},
		{"not failed", "apply", frozen(func(s *agentv1.DeploymentStatus) {
			s.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
		}), false},
		{"no error", "apply", frozen(func(s *agentv1.DeploymentStatus) { s.Error = nil }), false},
	} {
		if got := FrozenRefusal(tc.action, tc.status); got != tc.want {
			t.Errorf("%s: FrozenRefusal = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A refusal waiting for redelivery is "冻结中待补发": not failed, not
// retryable by hand; once redelivered it reads as an ignored old release.
func TestApplyFrozenMark(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		state, mark               string
		frozen, superseded, retry bool
	}{
		{"pending", "failed", FrozenMarkPending, true, false, false},
		{"redelivered", "failed", FrozenMarkRedelivered, false, true, false},
		{"no mark stays a failure", "failed", FrozenMarkNone, false, false, true},
		{"mark ignored off failed", "healthy", FrozenMarkPending, false, false, true},
	} {
		item := DeploymentSnapshot{State: tc.state, CanRetry: true}
		ApplyFrozenMark(&item, tc.mark)
		if item.Frozen != tc.frozen || item.Superseded != tc.superseded || item.CanRetry != tc.retry {
			t.Errorf("%s: %+v", tc.name, item)
		}
	}
}

// The failure threshold, cohort progress, automatic outcome and retries read
// SupersededDeploymentSQL: a frozen refusal (pending or redelivered) is in it.
func TestSupersededSQLCoversFrozenRefusals(t *testing.T) {
	if !strings.Contains(SupersededDeploymentSQL, "node_deployment_frozen_refusals") ||
		!strings.Contains(FrozenMarkSQL, "node_deployment_frozen_refusals") {
		t.Fatal("frozen refusals are not excluded from failures")
	}
}

func TestRolloutAggregateCountsFrozenApart(t *testing.T) {
	healthy := DeploymentSnapshot{State: "healthy"}
	frozen := DeploymentSnapshot{State: "failed", ErrorCode: "ERROR_CODE_FAILED_PRECONDITION", Frozen: true}
	failed := DeploymentSnapshot{State: "failed", ErrorCode: "ERROR_CODE_INTERNAL"}

	result := RolloutSnapshot{Action: "apply"}
	applyRolloutAggregate(&result, "queued", []DeploymentSnapshot{healthy, frozen})
	if result.State != RolloutStateSucceeded || result.Progress.Failed != 0 || result.Progress.Frozen != 1 ||
		result.Progress.Total != 2 || result.CanRetry {
		t.Fatalf("healthy + frozen = %+v", result)
	}
	result = RolloutSnapshot{Action: "apply"}
	applyRolloutAggregate(&result, "queued", []DeploymentSnapshot{healthy, frozen, failed})
	if result.State != RolloutStatePartialFailed || result.Progress.Failed != 1 || result.Progress.Frozen != 1 {
		t.Fatalf("frozen + failed = %+v", result)
	}
}
