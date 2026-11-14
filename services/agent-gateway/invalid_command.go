package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// terminableCommandDelivery is implemented by deliveries whose message can be
// terminated so the bus never redelivers it.
type terminableCommandDelivery interface {
	Term(context.Context) error
}

func (d *natsCommandDelivery) Term(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("command termination context is required")
	}
	if err := d.message.Term(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("terminate deployment command: %w", err)
	}
	return nil
}

const invalidCommandReasonLimit = 200

// rejectInvalidDurableCommand handles a durable deployment command that failed
// validation. The command can never become valid on a later delivery, so
// redelivering it only keeps the node from connecting. The message is
// terminated and, when the command still carries usable identifiers, the
// deployment is reported as failed with the validation reason. A nil result
// means the session continues; a non-nil result is the error that ends it.
// handled is false when the delivery cannot be terminated, in which case the
// caller keeps the previous behavior.
func (g *Gateway) rejectInvalidDurableCommand(
	ctx context.Context,
	nodeID string,
	delivery CommandDelivery,
	command *agentv1.DeploymentCommand,
	validationErr error,
	activeIdentityEnabled, multiTenantEnabled bool,
) (handled bool, err error) {
	terminable, ok := delivery.(terminableCommandDelivery)
	if !ok {
		return false, nil
	}
	reason := validationErr.Error()
	if len(reason) > invalidCommandReasonLimit {
		reason = reason[:invalidCommandReasonLimit]
	}
	reason = strings.ToValidUTF8(reason, "?")
	log.Printf("agent-gateway: warn: durable deployment command rejected node_id=%s deployment_id=%q attempt=%d reason=%q",
		nodeID, command.GetDeploymentId(), command.GetAttempt(), reason)

	statuses := g.invalidCommandStatuses(command, reason, multiTenantEnabled)
	for _, deploymentStatus := range statuses {
		if validateErr := g.validateDeploymentStatus(deploymentStatus, activeIdentityEnabled, multiTenantEnabled); validateErr != nil {
			log.Printf("agent-gateway: warn: rejected command cannot be reported node_id=%s deployment_id=%q reason=%q",
				nodeID, command.GetDeploymentId(), validateErr.Error())
			statuses = nil
			break
		}
	}
	for _, deploymentStatus := range statuses {
		publishCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		publication, publishErr := g.commands.PublishStatus(publishCtx, nodeID, deploymentStatus)
		cancel()
		if publishErr != nil || publication.Stream == "" || publication.Sequence == 0 {
			return true, status.Error(codes.Unavailable, "rejected deployment command status could not be persisted")
		}
	}
	termCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	if termErr := terminable.Term(termCtx); termErr != nil {
		return true, status.Error(codes.Unavailable, "rejected deployment command could not be terminated")
	}
	return true, nil
}

// invalidCommandStatuses builds the delivered and failed statuses that report
// a rejected command. The event identities derive from the deployment, so a
// replay publishes the same events. It returns nil when the command lacks the
// identifiers a status needs.
func (g *Gateway) invalidCommandStatuses(command *agentv1.DeploymentCommand, reason string, multiTenantEnabled bool) []*agentv1.DeploymentStatus {
	if command == nil || !canonicalUUID(command.DeploymentId) || command.Attempt == 0 || command.ConfigVersionId == "" {
		return nil
	}
	seed := fmt.Sprintf("gateway-rejected-command/%s/%d/%s", command.DeploymentId, command.Attempt, command.ConfigVersionId)
	requestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed+"/request")).String()
	correlationID := ""
	if command.Event != nil {
		if canonicalUUID(command.Event.RequestId) {
			requestID = command.Event.RequestId
		}
		if len(command.Event.CorrelationId) <= g.config.MaxEventMetadataBytes {
			correlationID = command.Event.CorrelationId
		}
	}
	now := timestamppb.New(g.now().UTC())
	build := func(state agentv1.NodeDeploymentState, sequence uint64, name string) *agentv1.DeploymentStatus {
		event := &commonv1.EventMetadata{
			EventId:       uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed+"/"+name)).String(),
			RequestId:     requestID,
			OccurredTime:  now,
			CorrelationId: correlationID,
		}
		if command.Event != nil && canonicalUUID(command.Event.EventId) {
			causation := command.Event.EventId
			event.CausationId = &causation
		}
		result := &agentv1.DeploymentStatus{
			Event: event, DeploymentId: command.DeploymentId, Attempt: command.Attempt,
			ConfigVersionId: command.ConfigVersionId, State: state, TransitionSequence: sequence,
		}
		if multiTenantEnabled && command.ConfigurationScopeId != nil {
			scope := command.GetConfigurationScopeId()
			result.ConfigurationScopeId = &scope
		}
		return result
	}
	delivered := build(agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1, "delivered")
	failed := build(agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2, "failed")
	failed.RunningConfigUnchanged = true
	failed.Error = &commonv1.ProtocolError{
		Code:    commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
		Message: "gateway rejected the durable deployment command: " + reason,
	}
	return []*agentv1.DeploymentStatus{delivered, failed}
}
