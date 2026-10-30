package edgestatus

import (
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestOPS09TerminalConfigConvergenceRequiresExactProbeAndIdentity(t *testing.T) {
	configID := uuid.New()
	status := &agentv1.DeploymentStatus{
		State:                          agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		ConfigVersionId:                configID.String(),
		ActiveConfigIdentityCapability: statusIdentityCapability(),
		ActiveConfigIdentity:           statusIdentity(configID.String(), 7),
		Checks: []*agentv1.CheckResult{{
			Name: "edge_active_config_probe", Succeeded: true,
			Summary: "active config runtime probe passed", LatencyDuration: durationpb.New(time.Second),
		}},
	}
	identity, err := normalizeStatusActiveIdentity(status)
	if err != nil {
		t.Fatal(err)
	}
	deployment := lockedDeployment{action: "apply"}
	if err := requireTerminalConfigConvergence(deployment, "healthy", status, identity); err != nil {
		t.Fatalf("exact convergence proof rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*agentv1.DeploymentStatus)
	}{
		{name: "missing probe", mutate: func(value *agentv1.DeploymentStatus) { value.Checks = nil }},
		{name: "failed probe", mutate: func(value *agentv1.DeploymentStatus) { value.Checks[0].Succeeded = false }},
		{name: "wrong probe summary", mutate: func(value *agentv1.DeploymentStatus) { value.Checks[0].Summary = "probe passed" }},
		{name: "missing probe latency", mutate: func(value *agentv1.DeploymentStatus) { value.Checks[0].LatencyDuration = nil }},
		{name: "missing active identity", mutate: func(value *agentv1.DeploymentStatus) { value.ActiveConfigIdentity = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneDeploymentStatusOPS09(status)
			test.mutate(candidate)
			candidateIdentity, normalizeErr := normalizeStatusActiveIdentity(candidate)
			if normalizeErr != nil {
				t.Fatal(normalizeErr)
			}
			if err := requireTerminalConfigConvergence(deployment, "healthy", candidate, candidateIdentity); !errors.Is(err, ErrBindingConflict) {
				t.Fatalf("convergence error = %v, want binding conflict", err)
			}
		})
	}

	rollback := cloneDeploymentStatusOPS09(status)
	rollback.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED
	rollbackIdentity, err := normalizeStatusActiveIdentity(rollback)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireTerminalConfigConvergence(lockedDeployment{action: "rollback"}, "reverted", rollback, rollbackIdentity); err != nil {
		t.Fatalf("rollback convergence proof rejected: %v", err)
	}
	rollback.ActiveConfigIdentity = nil
	if err := requireTerminalConfigConvergence(lockedDeployment{action: "rollback"}, "reverted", rollback, nil); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("rollback without identity error = %v, want binding conflict", err)
	}

	legacy := &agentv1.DeploymentStatus{State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY}
	if err := requireTerminalConfigConvergence(deployment, "healthy", legacy, nil); err != nil {
		t.Fatalf("legacy status compatibility changed: %v", err)
	}
}

func cloneDeploymentStatusOPS09(status *agentv1.DeploymentStatus) *agentv1.DeploymentStatus {
	return proto.Clone(status).(*agentv1.DeploymentStatus)
}
