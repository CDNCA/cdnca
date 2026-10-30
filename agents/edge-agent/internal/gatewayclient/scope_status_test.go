package gatewayclient

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func scopedTestCommand() *agentv1.DeploymentCommand {
	return &agentv1.DeploymentCommand{
		Event:        &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString()},
		DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: uuid.NewString(),
		ConfigurationScopeId: proto.String(uuid.NewString()),
	}
}

func TestScopedPreExecutionStatuses(t *testing.T) {
	command := scopedTestCommand()
	now := time.Now()
	queued := scopedQueuedStatus(command, now)
	started := scopedStartedStatus(command, now)
	superseded := scopedSupersededStatus(command, now)
	rejected := scopedQueueFullStatus(command, now)
	for _, test := range []struct {
		status    *agentv1.DeploymentStatus
		state     agentv1.NodeDeploymentState
		sequence  uint64
		unchanged bool
	}{
		{queued, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED, 2, false},
		{started, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, 3, false},
		{superseded, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED, 3, true},
		{rejected, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 3, true},
	} {
		if test.status.State != test.state || test.status.TransitionSequence != test.sequence ||
			test.status.RunningConfigUnchanged != test.unchanged ||
			test.status.GetConfigurationScopeId() != command.GetConfigurationScopeId() ||
			test.status.DeploymentId != command.DeploymentId || test.status.GetEvent().GetCausationId() != command.Event.EventId {
			t.Fatalf("status = %+v, want state %s sequence %d unchanged %v", test.status, test.state, test.sequence, test.unchanged)
		}
	}
	if rejected.Error == nil || rejected.Error.Code != commonv1.ErrorCode_ERROR_CODE_RATE_LIMITED || !rejected.Error.Retryable ||
		rejected.Error.RetryAfterDuration == nil || rejected.Error.RetryAfterDuration.AsDuration() <= 0 {
		t.Fatalf("queue-full error = %+v, want retryable RATE_LIMITED with retry_after", rejected.Error)
	}
	if queued.Event.EventId == started.Event.EventId || started.Event.EventId == superseded.Event.EventId {
		t.Fatal("distinct transitions share an event ID")
	}
	if again := scopedQueuedStatus(command, now.Add(time.Second)); again.Event.EventId != queued.Event.EventId {
		t.Fatal("queued status event ID is not stable across redelivery")
	}
}

func TestScopeExecutionStatusesShiftPastQueueAndStart(t *testing.T) {
	command := scopedTestCommand()
	legacy := []*agentv1.DeploymentStatus{
		statusFor(command, 2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, time.Now(), false, "", "", 0),
		failedStatus(command, 3, time.Now(), commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION, "precheck failed", false),
	}
	shifted := scopeExecutionStatuses(command, legacy)
	if len(shifted) != 2 || shifted[0].TransitionSequence != 4 || shifted[1].TransitionSequence != 5 {
		t.Fatalf("shifted sequences = %d,%d, want 4,5", shifted[0].TransitionSequence, shifted[1].TransitionSequence)
	}
	for index, status := range shifted {
		if status.GetConfigurationScopeId() != command.GetConfigurationScopeId() || status.State != legacy[index].State {
			t.Fatalf("shifted status = %+v", status)
		}
		if status.Event.EventId == legacy[index].Event.EventId {
			t.Fatal("shifted status reused the unshifted event ID")
		}
	}
	if legacy[0].TransitionSequence != 2 || legacy[0].ConfigurationScopeId != nil {
		t.Fatal("scopeExecutionStatuses mutated its input")
	}
}

// N13: a node clock behind the controller stamped STARTED before the
// command's (controller) time and the controller refused it permanently.
// Every deployment status is now at or after the command time; a clock ahead
// keeps its own time.
func TestDeploymentStatusesNeverPredateTheCommand(t *testing.T) {
	command := scopedTestCommand()
	commandTime := command.Event.OccurredTime.AsTime()
	behind, ahead := commandTime.Add(-30*time.Millisecond), commandTime.Add(30*time.Millisecond)
	for name, build := range map[string]func(time.Time) *agentv1.DeploymentStatus{
		"started":    func(at time.Time) *agentv1.DeploymentStatus { return scopedStartedStatus(command, at) },
		"superseded": func(at time.Time) *agentv1.DeploymentStatus { return scopedSupersededStatus(command, at) },
		"queue full": func(at time.Time) *agentv1.DeploymentStatus { return scopedQueueFullStatus(command, at) },
		"failed": func(at time.Time) *agentv1.DeploymentStatus {
			return failedStatus(command, 2, at, commonv1.ErrorCode_ERROR_CODE_INTERNAL, "x", false)
		},
		"journal": func(at time.Time) *agentv1.DeploymentStatus {
			return statusFor(command, 4, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, at, false, "", "", 0)
		},
	} {
		if got := build(behind).Event.OccurredTime.AsTime(); !got.Equal(commandTime) {
			t.Errorf("%s with node clock 30ms behind: occurred %s, want command time %s", name, got, commandTime)
		}
		if got := build(ahead).Event.OccurredTime.AsTime(); !got.Equal(ahead.UTC()) {
			t.Errorf("%s with node clock 30ms ahead: occurred %s, want %s", name, got, ahead)
		}
	}
}
