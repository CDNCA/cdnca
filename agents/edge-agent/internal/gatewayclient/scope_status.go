package gatewayclient

import (
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// On a MULTI_TENANT_RUNTIME session the wire sequence is DELIVERED(1),
// AGENT_QUEUED(2), then STARTED(3) or a terminal SUPERSEDED/queue-full
// FAILED(3); journal transitions after DELIVERED continue from 4.
const (
	scopedQueuedSequence    uint64 = 2
	scopedStartedSequence   uint64 = 3
	scopedExecutionSequence uint64 = 2 // added to every journal sequence > 1
	scopedQueueRetryAfter          = 30 * time.Second
)

func withCommandScope(command *agentv1.DeploymentCommand, status *agentv1.DeploymentStatus) *agentv1.DeploymentStatus {
	status.ConfigurationScopeId = proto.String(command.GetConfigurationScopeId())
	return status
}

func scopedQueuedStatus(command *agentv1.DeploymentCommand, _ time.Time) *agentv1.DeploymentStatus {
	// The queue position is part of command receipt, so a redelivered command
	// reproduces the identical status bytes from the command's own time.
	return withCommandScope(command, statusFor(command, scopedQueuedSequence,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED, command.Event.OccurredTime.AsTime(), false, "", "", 0))
}

func scopedStartedStatus(command *agentv1.DeploymentCommand, at time.Time) *agentv1.DeploymentStatus {
	return withCommandScope(command, statusFor(command, scopedStartedSequence,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, at, false, "", "", 0))
}

func scopedSupersededStatus(command *agentv1.DeploymentCommand, at time.Time) *agentv1.DeploymentStatus {
	return withCommandScope(command, statusFor(command, scopedStartedSequence,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED, at, true, "SUPERSEDED", "a newer deployment for this scope replaced it before it started", 0))
}

func scopedQueueFullStatus(command *agentv1.DeploymentCommand, at time.Time) *agentv1.DeploymentStatus {
	status := failedStatus(command, scopedStartedSequence, at, commonv1.ErrorCode_ERROR_CODE_RATE_LIMITED,
		fmt.Sprintf("node deployment queue is full (%d)", multiTenantDeploymentQueueLimit), true)
	status.Error.RetryAfterDuration = durationpb.New(scopedQueueRetryAfter)
	return withCommandScope(command, status)
}

// scopeExecutionStatuses renumbers journal-derived statuses past AGENT_QUEUED
// and STARTED and binds them to the command's scope. Event IDs are derived
// from the shifted sequence so they stay unique and redelivery-stable.
func scopeExecutionStatuses(command *agentv1.DeploymentCommand, statuses []*agentv1.DeploymentStatus) []*agentv1.DeploymentStatus {
	shifted := make([]*agentv1.DeploymentStatus, len(statuses))
	for index, status := range statuses {
		value := proto.Clone(status).(*agentv1.DeploymentStatus)
		if value.TransitionSequence > 1 {
			value.TransitionSequence += scopedExecutionSequence
			value.Event.EventId = uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s:%d:%d",
				command.Event.EventId, value.TransitionSequence, value.State))).String()
		}
		shifted[index] = withCommandScope(command, value)
	}
	return shifted
}
