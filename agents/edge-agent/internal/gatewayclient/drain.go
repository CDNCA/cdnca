package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/drainruntime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const drainControlAPIVersion uint32 = 1

type DrainPlanHandler interface {
	HandleDrainPlan(context.Context, drainruntime.Plan) (drainruntime.Result, error)
}

type drainCommandAwareHandler interface {
	HandleDrainPlanCommand(context.Context, drainruntime.Plan, time.Time) (drainruntime.Result, error)
}

func WithDrainPlanHandler(handler DrainPlanHandler) ClientOption {
	return func(client *Client) error {
		if handler == nil {
			return fmt.Errorf("%w: drain plan handler is required", ErrInvalidConfiguration)
		}
		client.drain = handler
		return nil
	}
}

func negotiateDrainControlV1(gateway *agentv1.GatewayHello, local *agentv1.AgentCapabilities) (bool, error) {
	localV1, err := singleCapabilityV1(local.GetFeatures(), agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL, "local drain")
	if err != nil {
		return false, err
	}
	gatewayV1, err := singleCapabilityV1(gateway.GetEnabledCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL, "Gateway drain")
	if err != nil {
		return false, err
	}
	if gatewayV1 && !localV1 {
		return false, fmt.Errorf("%w: Gateway enabled an unadvertised drain capability", ErrInvalidMessage)
	}
	return gatewayV1 && localV1, nil
}

func singleCapabilityV1(capabilities []*agentv1.Capability, name agentv1.CapabilityName, label string) (bool, error) {
	found := false
	for _, capability := range capabilities {
		if capability.GetName() != name {
			continue
		}
		if found || capability.GetApiVersion() != drainControlAPIVersion {
			return false, fmt.Errorf("%w: %s capability is duplicated or unsupported", ErrInvalidMessage, label)
		}
		found = true
	}
	return found, nil
}

func (c *Client) dispatchDrainCommand(ctx context.Context, command *agentv1.DrainCommand) (*agentv1.DrainStatus, error) {
	return HandleDrainCommand(ctx, c.drain, command, c.config.NodeID, c.config.MaxCommandBytes, c.now())
}

func HandleDrainCommand(ctx context.Context, handler DrainPlanHandler, command *agentv1.DrainCommand,
	nodeID string, maxCommandBytes int, now time.Time,
) (*agentv1.DrainStatus, error) {
	if handler == nil || nodeID == "" || maxCommandBytes <= 0 {
		return nil, fmt.Errorf("%w: drain command dependencies are invalid", ErrInvalidConfiguration)
	}
	config := DefaultConfig()
	config.NodeID = nodeID
	config.MaxCommandBytes = maxCommandBytes
	plan, digest, err := validateDrainCommand(command, config, now)
	if err != nil {
		return nil, err
	}
	var result drainruntime.Result
	var processErr error
	if aware, ok := handler.(drainCommandAwareHandler); ok {
		result, processErr = aware.HandleDrainPlanCommand(ctx, plan, command.DeadlineTime.AsTime().UTC())
	} else {
		result, processErr = handler.HandleDrainPlan(ctx, plan)
	}
	return drainStatus(command, digest, result, processErr), nil
}

func validateDrainCommand(command *agentv1.DrainCommand, config Config, now time.Time) (drainruntime.Plan, [sha256.Size]byte, error) {
	if command == nil || proto.Size(command) > config.MaxCommandBytes || command.Event == nil ||
		!canonicalUUID(command.Event.EventId) || !canonicalUUID(command.Event.RequestId) ||
		command.Event.OccurredTime == nil || command.Event.OccurredTime.CheckValid() != nil ||
		command.Schema != agentv1.DrainSchema_DRAIN_SCHEMA_V1 || !canonicalUUID(command.CommandId) ||
		command.NodeId != config.NodeID || !canonicalUUID(command.NodeId) || !safeIdentifier(command.PlanId) ||
		command.Revision == 0 || len(command.PlanSha256) != sha256.Size || len(command.CanonicalPlanJson) == 0 ||
		command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil || !command.DeadlineTime.AsTime().After(now) ||
		command.DeadlineTime.AsTime().After(now.Add(25*time.Hour)) {
		return drainruntime.Plan{}, [sha256.Size]byte{}, fmt.Errorf("%w: drain command identity or deadline is invalid", ErrInvalidMessage)
	}
	if command.Event.TaskId == nil || command.Event.GetTaskId() != command.CommandId || cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return drainruntime.Plan{}, [sha256.Size]byte{}, fmt.Errorf("%w: drain command event or fields are invalid", ErrInvalidMessage)
	}
	var plan drainruntime.Plan
	if err := json.Unmarshal(command.CanonicalPlanJson, &plan); err != nil {
		return drainruntime.Plan{}, [sha256.Size]byte{}, fmt.Errorf("%w: drain plan JSON is invalid", ErrInvalidMessage)
	}
	compiled, err := drainruntime.Compile(plan)
	if err != nil || plan.PlanID != command.PlanId || plan.Revision != command.Revision ||
		!bytes.Equal(compiled.CanonicalJSON, command.CanonicalPlanJson) {
		return drainruntime.Plan{}, [sha256.Size]byte{}, fmt.Errorf("%w: drain plan is not canonical or bound to the command", ErrInvalidMessage)
	}
	digest := sha256.Sum256(command.CanonicalPlanJson)
	if !bytes.Equal(digest[:], command.PlanSha256) {
		return drainruntime.Plan{}, [sha256.Size]byte{}, fmt.Errorf("%w: drain plan digest is invalid", ErrInvalidMessage)
	}
	return plan, digest, nil
}

func drainStatus(command *agentv1.DrainCommand, digest [sha256.Size]byte, result drainruntime.Result, processErr error) *agentv1.DrainStatus {
	phase := drainProtoPhase(result.Phase)
	errorCode := drainErrorCode(processErr)
	pending := phase != agentv1.DrainPhase_DRAIN_PHASE_COMPLETED && phase != agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK
	degraded := phase == agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK ||
		errors.Is(processErr, drainruntime.ErrDrainDeadlineExceeded) ||
		errors.Is(processErr, drainruntime.ErrDrainObservationFailed)
	if processErr != nil && !resumableDrainCommandError(processErr) && phase != agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK {
		phase = agentv1.DrainPhase_DRAIN_PHASE_FAILED
		pending = false
		degraded = true
	}
	if phase == agentv1.DrainPhase_DRAIN_PHASE_UNSPECIFIED {
		phase = agentv1.DrainPhase_DRAIN_PHASE_FAILED
		pending = false
		degraded = true
		if errorCode == "" {
			errorCode = "DRAIN_RUNTIME_FAILED"
		}
	}
	statusRevision := uint64(len(result.Transitions))
	occurred := command.Event.OccurredTime.AsTime().UTC()
	if statusRevision == 0 {
		statusRevision = 1
	} else {
		last := result.Transitions[len(result.Transitions)-1]
		occurred = last.At.UTC()
		if errorCode == "" {
			errorCode = last.ErrorCode
		}
	}
	remaining := uint32(result.RemainingOldWorkers)
	if result.RemainingOldWorkers < 0 || uint64(result.RemainingOldWorkers) > math.MaxUint32 {
		remaining = 0
		phase = agentv1.DrainPhase_DRAIN_PHASE_FAILED
		pending = false
		degraded = true
		errorCode = "DRAIN_RUNTIME_INVALID_STATE"
	}
	taskID := command.CommandId
	causationID := command.Event.EventId
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("drain:%s:%d:%d:%s", command.CommandId, statusRevision, phase, errorCode))).String()
	return &agentv1.DrainStatus{
		Event: &commonv1.EventMetadata{EventId: eventID, RequestId: command.Event.RequestId,
			OccurredTime: timestamppb.New(occurred), Traceparent: command.Event.Traceparent,
			CausationId: &causationID, CorrelationId: command.Event.CorrelationId, TaskId: &taskID},
		Schema: command.Schema, CommandId: command.CommandId, NodeId: command.NodeId,
		PlanId: command.PlanId, Revision: command.Revision, PlanSha256: append([]byte(nil), digest[:]...),
		Phase: phase, StatusRevision: statusRevision, Pending: pending, Degraded: degraded,
		RemainingOldWorkers: remaining, ForcedTermination: result.ForcedTermination, ErrorCode: errorCode,
	}
}

func resumableDrainCommandError(err error) bool {
	return errors.Is(err, drainruntime.ErrHealthPending) || errors.Is(err, drainruntime.ErrDrainInProgress) ||
		errors.Is(err, drainruntime.ErrDrainObservationFailed) || errors.Is(err, drainruntime.ErrDrainDeadlineExceeded)
}

func drainProtoPhase(phase drainruntime.Phase) agentv1.DrainPhase {
	switch phase {
	case drainruntime.PhasePrecheck:
		return agentv1.DrainPhase_DRAIN_PHASE_PRECHECK
	case drainruntime.PhaseActivateNew:
		return agentv1.DrainPhase_DRAIN_PHASE_ACTIVATE_NEW
	case drainruntime.PhaseHealthGate:
		return agentv1.DrainPhase_DRAIN_PHASE_HEALTH_GATE
	case drainruntime.PhaseDrainingOld:
		return agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD
	case drainruntime.PhaseCompleted:
		return agentv1.DrainPhase_DRAIN_PHASE_COMPLETED
	case drainruntime.PhaseRolledBack:
		return agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK
	default:
		return agentv1.DrainPhase_DRAIN_PHASE_UNSPECIFIED
	}
}

func drainErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, drainruntime.ErrHealthPending):
		return "HEALTH_PENDING"
	case errors.Is(err, drainruntime.ErrDrainInProgress):
		return "DRAIN_IN_PROGRESS"
	case errors.Is(err, drainruntime.ErrDrainObservationFailed):
		return "DRAIN_OBSERVATION_FAILED"
	case errors.Is(err, drainruntime.ErrDrainDeadlineExceeded):
		return "DRAIN_DEADLINE_EXCEEDED"
	case errors.Is(err, drainruntime.ErrInvalidPlan):
		return "INVALID_PLAN"
	case errors.Is(err, drainruntime.ErrConflict):
		return "REVISION_CONFLICT"
	case errors.Is(err, drainruntime.ErrStaleRevision):
		return "STALE_REVISION"
	case errors.Is(err, drainruntime.ErrCorruptState):
		return "CORRUPT_STATE"
	case errors.Is(err, drainruntime.ErrRollbackFailed):
		return "ROLLBACK_FAILED"
	default:
		return "DRAIN_RUNTIME_FAILED"
	}
}

func sendDrainStatus(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, status *agentv1.DrainStatus, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now), Payload: &agentv1.ConnectRequest_DrainStatus{DrainStatus: status}})
}
