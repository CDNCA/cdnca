package l4lineswitch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/l4drain"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

var natsTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type DrainPlanSource interface {
	Plans(context.Context, Actor, Switch) (map[uuid.UUID]l4drain.Plan, error)
}

type JetStreamDrainConfig struct {
	Publisher     l4drain.PublisherConfig
	StatusStream  string
	StatusPrefix  string
	StatusTimeout time.Duration
}

func DefaultJetStreamDrainConfig() JetStreamDrainConfig {
	return JetStreamDrainConfig{
		Publisher: l4drain.DefaultPublisherConfig(), StatusStream: "AGENT_DEPLOYMENT_STATUS",
		StatusPrefix: "cdnca.agent.deployment-status.drain", StatusTimeout: 5 * time.Second,
	}
}

type JetStreamDrainCoordinator struct {
	plans     DrainPlanSource
	publisher *l4drain.Publisher
	js        nats.JetStreamContext
	config    JetStreamDrainConfig
	now       func() time.Time
}

func NewJetStreamDrainCoordinator(connection *nats.Conn, plans DrainPlanSource, config JetStreamDrainConfig, now func() time.Time) (*JetStreamDrainCoordinator, error) {
	if connection == nil || connection.IsClosed() || plans == nil || now == nil ||
		!natsTokenPattern.MatchString(config.StatusStream) || !validSubjectPrefix(config.StatusPrefix) ||
		config.StatusTimeout <= 0 || config.StatusTimeout > time.Minute {
		return nil, ErrInvalidInput
	}
	publisher, err := l4drain.NewPublisher(connection, config.Publisher)
	if err != nil {
		return nil, err
	}
	js, err := connection.JetStream(nats.MaxWait(config.StatusTimeout))
	if err != nil {
		return nil, fmt.Errorf("%w: create drain status context", ErrPersistence)
	}
	return &JetStreamDrainCoordinator{plans: plans, publisher: publisher, js: js, config: config, now: now}, nil
}

func (coordinator *JetStreamDrainCoordinator) Build(ctx context.Context, actor Actor, value Switch) (map[uuid.UUID]*agentv1.DrainCommand, error) {
	if ctx == nil || coordinator == nil || !validAuthority(actor) || value.ID == uuid.Nil || value.RequestID == uuid.Nil ||
		value.CreatedAt.IsZero() || !value.Deadline.After(value.CreatedAt) {
		return nil, ErrInvalidInput
	}
	plans, err := coordinator.plans.Plans(ctx, actor, value)
	if err != nil {
		return nil, err
	}
	if len(plans) != 0 && len(plans) != len(value.RetiringNodes) {
		return nil, ErrConflict
	}
	occurredAt := value.CreatedAt.UTC()
	result := make(map[uuid.UUID]*agentv1.DrainCommand, len(plans))
	for _, nodeID := range value.RetiringNodes {
		plan, exists := plans[nodeID]
		if !exists {
			return nil, ErrConflict
		}
		commandID := uuid.NewSHA1(value.ID, nodeID[:])
		command, err := l4drain.BuildCommand(l4drain.CommandInput{
			CommandID: commandID.String(), NodeID: nodeID.String(), RequestID: value.RequestID.String(),
			CorrelationID: value.CorrelationID.String(), Traceparent: value.Traceparent,
			OccurredAt: occurredAt, Deadline: value.Deadline, Plan: plan,
		})
		if err != nil {
			return nil, err
		}
		result[nodeID] = command
	}
	return result, nil
}

func (coordinator *JetStreamDrainCoordinator) Publish(ctx context.Context, actor Actor, command *agentv1.DrainCommand) error {
	if ctx == nil || coordinator == nil || !validAuthority(actor) {
		return ErrInvalidInput
	}
	_, err := coordinator.publisher.Publish(ctx, command)
	return err
}

func (coordinator *JetStreamDrainCoordinator) Status(ctx context.Context, actor Actor, command *agentv1.DrainCommand) (string, error) {
	if ctx == nil || coordinator == nil || !validAuthority(actor) || command == nil ||
		command.Event == nil || command.Schema != agentv1.DrainSchema_DRAIN_SCHEMA_V1 || command.CommandId == "" || command.NodeId == "" ||
		command.PlanId == "" || command.Revision == 0 || len(command.PlanSha256) != 32 {
		return "", ErrInvalidInput
	}
	nodeID, err := uuid.Parse(command.NodeId)
	if err != nil || nodeID == uuid.Nil || nodeID.String() != command.NodeId {
		return "", ErrInvalidInput
	}
	commandID, err := uuid.Parse(command.CommandId)
	if err != nil || commandID == uuid.Nil || commandID.String() != command.CommandId {
		return "", ErrInvalidInput
	}
	message, statusRevision, err := coordinator.latestStatusMessage(ctx, command.NodeId, command.CommandId)
	if errors.Is(err, nats.ErrMsgNotFound) || errors.Is(err, nats.ErrStreamNotFound) {
		return DrainPending, nil
	}
	if err != nil {
		return "", err
	}
	var status agentv1.DrainStatus
	if message == nil || message.Sequence == 0 || len(message.Data) == 0 || len(message.Data) > 1<<20 ||
		proto.Unmarshal(message.Data, &status) != nil || !validDrainStatus(&status, command, statusRevision) {
		return "", ErrConflict
	}
	switch status.Phase {
	case agentv1.DrainPhase_DRAIN_PHASE_PRECHECK, agentv1.DrainPhase_DRAIN_PHASE_ACTIVATE_NEW,
		agentv1.DrainPhase_DRAIN_PHASE_HEALTH_GATE, agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD:
		return DrainPending, nil
	case agentv1.DrainPhase_DRAIN_PHASE_COMPLETED:
		return DrainCompleted, nil
	case agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK, agentv1.DrainPhase_DRAIN_PHASE_FAILED:
		return DrainFailed, nil
	default:
		return "", ErrConflict
	}
}

func (coordinator *JetStreamDrainCoordinator) latestStatusMessage(ctx context.Context, nodeID, commandID string) (*nats.RawStreamMsg, uint64, error) {
	operationCtx, cancel := context.WithTimeout(ctx, coordinator.config.StatusTimeout)
	info, err := coordinator.js.StreamInfo(coordinator.config.StatusStream,
		&nats.StreamInfoRequest{SubjectsFilter: coordinator.config.StatusPrefix + ".>"}, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read drain status subjects", ErrPersistence)
	}
	if info == nil {
		return nil, 0, ErrConflict
	}
	prefix := coordinator.config.StatusPrefix + "." + nodeID + "_" + commandID + "_"
	var subject string
	var revision uint64
	for candidate, count := range info.State.Subjects {
		if !strings.HasPrefix(candidate, prefix) {
			continue
		}
		if count != 1 {
			return nil, 0, ErrConflict
		}
		raw := strings.TrimPrefix(candidate, prefix)
		parsed, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != raw {
			return nil, 0, ErrConflict
		}
		if parsed > revision {
			subject, revision = candidate, parsed
		}
	}
	if subject == "" {
		return nil, 0, nats.ErrMsgNotFound
	}
	operationCtx, cancel = context.WithTimeout(ctx, coordinator.config.StatusTimeout)
	message, err := coordinator.js.GetLastMsg(coordinator.config.StatusStream, subject, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read drain status", ErrPersistence)
	}
	if message == nil || message.Subject != subject {
		return nil, 0, ErrConflict
	}
	return message, revision, nil
}

func validDrainStatus(status *agentv1.DrainStatus, command *agentv1.DrainCommand, expectedRevision uint64) bool {
	if status == nil || status.Event == nil || status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil ||
		status.Event.RequestId != command.Event.RequestId || status.Event.GetCausationId() != command.Event.EventId ||
		status.Event.GetTaskId() != command.CommandId || status.Schema != command.Schema ||
		status.CommandId != command.CommandId || status.NodeId != command.NodeId || status.PlanId != command.PlanId ||
		status.Revision != command.Revision || !bytes.Equal(status.PlanSha256, command.PlanSha256) ||
		status.StatusRevision != expectedRevision || status.StatusRevision == 0 || status.ForcedTermination ||
		len(status.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	switch status.Phase {
	case agentv1.DrainPhase_DRAIN_PHASE_PRECHECK, agentv1.DrainPhase_DRAIN_PHASE_ACTIVATE_NEW,
		agentv1.DrainPhase_DRAIN_PHASE_HEALTH_GATE, agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD:
		return status.Pending
	case agentv1.DrainPhase_DRAIN_PHASE_COMPLETED:
		return !status.Pending && !status.Degraded && status.RemainingOldWorkers == 0 && status.ErrorCode == ""
	case agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK, agentv1.DrainPhase_DRAIN_PHASE_FAILED:
		return !status.Pending && status.Degraded && status.ErrorCode != ""
	default:
		return false
	}
}

func validSubjectPrefix(value string) bool {
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !natsTokenPattern.MatchString(token) {
			return false
		}
	}
	return true
}
