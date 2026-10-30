package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	activeConfigProbeCheckName    = "edge_active_config_probe"
	activeConfigProbeCheckSummary = "active config runtime probe passed"
	// PostActivationMaintenanceCheckName is the failed check of a deployment
	// activated whose bookkeeping afterwards failed (PJ-E02).
	PostActivationMaintenanceCheckName = "edge_post_activation_maintenance"
)

func deliveredStatus(command *agentv1.DeploymentCommand) *agentv1.DeploymentStatus {
	return statusFor(command, 1, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, command.Event.OccurredTime.AsTime(), false, "", "", 0)
}

func failedStatus(command *agentv1.DeploymentCommand, sequence uint64, at time.Time, code commonv1.ErrorCode, summary string, retryable bool) *agentv1.DeploymentStatus {
	status := statusFor(command, sequence, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, at, true, "FAILED", summary, 0)
	status.Error = &commonv1.ProtocolError{Code: code, Message: sanitizeSummary(summary), Retryable: retryable}
	return status
}

func statusesForResult(command *agentv1.DeploymentCommand, result deployment.Result) []*agentv1.DeploymentStatus {
	statuses := make([]*agentv1.DeploymentStatus, 0, len(result.Transitions)-1)
	for index, transition := range result.Transitions {
		if transition.Sequence == 1 {
			continue
		}
		latency := time.Duration(0)
		if index > 0 && transition.At.After(result.Transitions[index-1].At) {
			latency = transition.At.Sub(result.Transitions[index-1].At)
		}
		state := wireState(transition.State)
		status := statusFor(command, transition.Sequence, state, transition.At, transition.RunningConfigUnchanged, transition.ErrorCode, transition.Summary, latency)
		if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY ||
			state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
			status.Checks = append(status.Checks, &agentv1.CheckResult{
				Name: activeConfigProbeCheckName, Succeeded: true,
				Summary: activeConfigProbeCheckSummary, LatencyDuration: durationpb.New(latency),
			})
			if transition.MaintenanceFailure != "" {
				status.Checks = append(status.Checks, &agentv1.CheckResult{
					Name: PostActivationMaintenanceCheckName, Succeeded: false,
					Summary: sanitizeSummary(transition.MaintenanceFailure), LatencyDuration: durationpb.New(0),
				})
			}
		}
		if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
			status.Error = &commonv1.ProtocolError{
				Code:    errorCode(transition.ErrorCode),
				Message: sanitizeSummary(transition.Summary),
			}
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// notBeforeCommand keeps a status time at or after its command's (controller
// clock) time: the controller refuses a status that predates its command, and
// a node clock tens of milliseconds behind the controller produced exactly
// that for a STARTED sent right after delivery (N13).
func notBeforeCommand(commandTime *timestamppb.Timestamp, at time.Time) time.Time {
	if commandTime != nil && commandTime.CheckValid() == nil && at.Before(commandTime.AsTime()) {
		return commandTime.AsTime()
	}
	return at
}

func statusFor(command *agentv1.DeploymentCommand, sequence uint64, state agentv1.NodeDeploymentState, at time.Time, unchanged bool, code, summary string, latency time.Duration) *agentv1.DeploymentStatus {
	at = notBeforeCommand(command.Event.OccurredTime, at)
	causationID := command.Event.EventId
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s:%d:%d", command.Event.EventId, sequence, state))).String()
	status := &agentv1.DeploymentStatus{
		Event: &commonv1.EventMetadata{
			EventId:       eventID,
			RequestId:     command.Event.RequestId,
			OccurredTime:  timestamppb.New(at.UTC()),
			Traceparent:   command.Event.Traceparent,
			CausationId:   &causationID,
			CorrelationId: command.Event.CorrelationId,
			TaskId:        command.Event.TaskId,
		},
		DeploymentId:           command.DeploymentId,
		Attempt:                command.Attempt,
		ConfigVersionId:        command.ConfigVersionId,
		State:                  state,
		TransitionSequence:     sequence,
		RunningConfigUnchanged: unchanged,
	}
	if code != "" || summary != "" || latency > 0 {
		checkSummary := sanitizeSummary(summary)
		if summary == "" && state != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED && state != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
			checkSummary = "transition completed"
		}
		status.Checks = []*agentv1.CheckResult{{
			Name:            "edge_deployment_transition",
			Succeeded:       state != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED && state != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
			Summary:         checkSummary,
			LatencyDuration: durationpb.New(latency),
		}}
	}
	return status
}

func wireState(state deployment.State) agentv1.NodeDeploymentState {
	switch state {
	case deployment.StateDelivered:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED
	case deployment.StateStaged:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED
	case deployment.StatePrechecked:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED
	case deployment.StateActivated:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED
	case deployment.StateHealthy:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY
	case deployment.StateFailed:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
	case deployment.StateReverting:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING
	case deployment.StateReverted:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED
	case deployment.StateRollbackFailed:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED
	default:
		return agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
	}
}

func errorCode(code string) commonv1.ErrorCode {
	switch code {
	case "DIGEST_MISMATCH", "RELEASE_INVALID", "ROLLBACK_TARGET_INVALID", "ROLLBACK_BASELINE_INVALID":
		return commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH
	case "PREVIOUS_VERSION_MISMATCH", "ROLLBACK_TARGET_UNAVAILABLE", "ROLLBACK_TARGET_MISMATCH", "ROLLBACK_BASELINE_MISMATCH":
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION
	case "PRECHECK_FAILED", "HEALTH_FAILED", "ROLLBACK_PRECHECK_FAILED", "ROLLBACK_ACTIVATION_FAILED", "ROLLBACK_HEALTH_FAILED", "ROLLBACK_RESTORE_FAILED":
		return commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE
	case "INVALID_PATH", "STAGE_FAILED":
		return commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	// Refused before activation, running config unchanged (dynamic routing
	// scope journal): the node already runs a newer revision, or this release
	// was rolled back. The controller shows these as an ignored old release.
	case "STALE_CONFIGURATION_REVISION":
		return commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT
	case "CONFIGURATION_ROLLED_BACK":
		return commonv1.ErrorCode_ERROR_CODE_REVOKED
	case "CONFIGURATION_REVISION_CONFLICT":
		return commonv1.ErrorCode_ERROR_CODE_CONFLICT
	default:
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL
	}
}

func classifyError(err error) commonv1.ErrorCode {
	switch {
	case errors.Is(err, ErrUnsupportedCommand):
		return commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION
	case errors.Is(err, ErrArtifactIntegrity):
		return commonv1.ErrorCode_ERROR_CODE_DIGEST_MISMATCH
	case errors.Is(err, ErrCommandConflict), errors.Is(err, deployment.ErrConflict):
		return commonv1.ErrorCode_ERROR_CODE_CONFLICT
	case errors.Is(err, deployment.ErrStaleAttempt):
		return commonv1.ErrorCode_ERROR_CODE_STALE_ATTEMPT
	case errors.Is(err, context.DeadlineExceeded):
		return commonv1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED
	case errors.Is(err, ErrInvalidMessage), errors.Is(err, deployment.ErrInvalidCommand), errors.Is(err, deployment.ErrInvalidPath):
		return commonv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	default:
		return commonv1.ErrorCode_ERROR_CODE_INTERNAL
	}
}

func sanitizeSummary(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 512 {
		value = value[:512]
	}
	if value == "" {
		return "deployment operation failed"
	}
	return value
}

// WithDeploymentChecks adds checks (for example the OWASP CRS engine gate)
// to the HEALTHY / REVERTED status of every deployment.
func WithDeploymentChecks(checks func() []*agentv1.CheckResult) ClientOption {
	return func(client *Client) error {
		if checks == nil || client == nil {
			return ErrInvalidConfiguration
		}
		client.extraChecks = checks
		return nil
	}
}

func appendTerminalChecks(statuses []*agentv1.DeploymentStatus, checks func() []*agentv1.CheckResult) {
	if checks == nil {
		return
	}
	for _, status := range statuses {
		if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
			status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
			continue
		}
		names := map[string]bool{}
		for _, check := range status.Checks {
			names[check.Name] = true
		}
		for _, check := range checks() {
			if check != nil && !names[check.Name] {
				check.Summary = sanitizeSummary(check.Summary)
				status.Checks = append(status.Checks, check)
				names[check.Name] = true
			}
		}
	}
}
