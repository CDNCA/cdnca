package edgedeployment

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
)

func failedStatusPayload(t *testing.T, code commonv1.ErrorCode, unchanged bool) []byte {
	t.Helper()
	payload, err := proto.Marshal(&agentv1.DeploymentStatus{
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, RunningConfigUnchanged: unchanged,
		Error: &commonv1.ProtocolError{Code: code, Message: "refused"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// fix-cfgflow2 §1: the node refused an old APPLY before activation (it runs a
// newer revision, or this release was rolled back): an ignored old release.
func TestDeploymentSupersededOnlyForUnchangedStaleOrRolledBack(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     string
		code      string
		unchanged bool
		want      bool
	}{
		{"stale", "failed", "ERROR_CODE_STALE_ATTEMPT", true, true},
		{"rolled back", "failed", "ERROR_CODE_REVOKED", true, true},
		{"conflict stays failed", "failed", "ERROR_CODE_CONFLICT", true, false},
		{"internal stays failed", "failed", "ERROR_CODE_INTERNAL", true, false},
		{"changed running config stays failed", "failed", "ERROR_CODE_STALE_ATTEMPT", false, false},
		{"rollback_failed stays failed", "rollback_failed", "ERROR_CODE_STALE_ATTEMPT", true, false},
		{"healthy", "healthy", "", true, false},
	} {
		if got := DeploymentSuperseded(tc.state, tc.code, tc.unchanged); got != tc.want {
			t.Errorf("%s: DeploymentSuperseded = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRolloutAggregateCountsIgnoredOldReleaseApart(t *testing.T) {
	stale := DeploymentSnapshot{State: "failed", ErrorCode: "ERROR_CODE_STALE_ATTEMPT", Superseded: true}
	healthy := DeploymentSnapshot{State: "healthy"}
	failed := DeploymentSnapshot{State: "failed", ErrorCode: "ERROR_CODE_INTERNAL"}

	result := RolloutSnapshot{Action: "apply"}
	applyRolloutAggregate(&result, "queued", []DeploymentSnapshot{healthy, stale})
	if result.State != RolloutStateSucceeded || result.Progress.Failed != 0 || result.Progress.Superseded != 1 ||
		result.Progress.Succeeded != 1 || result.Progress.Total != 2 || result.CanRetry {
		t.Fatalf("healthy + ignored old release = %+v", result)
	}

	result = RolloutSnapshot{Action: "apply"}
	applyRolloutAggregate(&result, "queued", []DeploymentSnapshot{stale})
	if result.State != RolloutStateSucceeded || result.Progress.Superseded != 1 || result.Progress.Failed != 0 {
		t.Fatalf("only ignored old release = %+v", result)
	}

	result = RolloutSnapshot{Action: "apply"}
	applyRolloutAggregate(&result, "queued", []DeploymentSnapshot{stale, failed})
	if result.State != RolloutStateFailed || result.Progress.Failed != 1 || result.Progress.Superseded != 1 {
		t.Fatalf("ignored + failed = %+v", result)
	}

	result = RolloutSnapshot{Action: "apply", Policy: RolloutPolicy{Strategy: RolloutStrategyCanary}}
	applyRolloutAggregate(&result, "completed", []DeploymentSnapshot{healthy, stale})
	if result.State != RolloutStateSucceeded {
		t.Fatalf("canary completed with ignored old release = %+v", result)
	}
}

func TestDeploymentStatusErrorCodeReadsTheProtocolError(t *testing.T) {
	code, unchanged := DeploymentStatusError(failedStatusPayload(t, commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT, true))
	if code != "ERROR_CODE_STALE_ATTEMPT" || !unchanged {
		t.Fatalf("DeploymentStatusError = %q %v", code, unchanged)
	}
	if code, _ := DeploymentStatusError(nil); code != "" {
		t.Fatalf("empty payload code = %q", code)
	}
}
