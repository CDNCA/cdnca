package gateway

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testDrainDelivery struct {
	command *agentv1.DrainCommand
	acked   int
	retried int
	delay   time.Duration
}

func (delivery *testDrainDelivery) Command() *agentv1.DrainCommand { return delivery.command }
func (delivery *testDrainDelivery) Ack(context.Context) error {
	delivery.acked++
	return nil
}
func (delivery *testDrainDelivery) Retry(_ context.Context, delay time.Duration) error {
	delivery.retried++
	delivery.delay = delay
	return nil
}

type testDrainBus struct {
	published []*agentv1.DrainStatus
}

func (*testDrainBus) SubscribeDrain(context.Context, string) (DrainCommandSubscription, error) {
	return nil, nil
}
func (bus *testDrainBus) PublishDrainStatus(_ context.Context, _ string, value *agentv1.DrainStatus) (DrainStatusPublication, error) {
	bus.published = append(bus.published, value)
	return DrainStatusPublication{Stream: "AGENT_DEPLOYMENT_STATUS", Sequence: uint64(len(bus.published))}, nil
}

func TestDrainStatusPersistsBeforeRetryAndTerminalAck(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	command := gatewayDrainCommand(now)
	if err := validateDrainCommand(command, command.NodeId, now); err != nil {
		t.Fatal(err)
	}
	bus := &testDrainBus{}
	gateway := &Gateway{config: DefaultConfig(), drain: bus}
	delivery := &testDrainDelivery{command: command}
	pending := pendingDrainCommandSet{command.CommandId: {command: command, deliveries: []DrainCommandDelivery{delivery}}}

	status := gatewayDrainStatus(command, now.Add(time.Second), agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD, true, "DRAIN_IN_PROGRESS")
	if err := gateway.persistDrainStatusAndAdvance(t.Context(), command.NodeId, status, pending); err != nil {
		t.Fatal(err)
	}
	if len(bus.published) != 1 || delivery.retried != 1 || delivery.acked != 0 || delivery.delay != time.Second || len(pending) != 0 {
		t.Fatalf("pending result: published=%d retried=%d acked=%d delay=%s pending=%d", len(bus.published), delivery.retried, delivery.acked, delivery.delay, len(pending))
	}

	delivery = &testDrainDelivery{command: command}
	pending[command.CommandId] = &pendingDrainCommand{command: command, deliveries: []DrainCommandDelivery{delivery}}
	status = gatewayDrainStatus(command, now.Add(2*time.Second), agentv1.DrainPhase_DRAIN_PHASE_COMPLETED, false, "")
	if err := gateway.persistDrainStatusAndAdvance(t.Context(), command.NodeId, status, pending); err != nil {
		t.Fatal(err)
	}
	if len(bus.published) != 2 || delivery.acked != 1 || delivery.retried != 0 || len(pending) != 0 {
		t.Fatalf("terminal result: published=%d retried=%d acked=%d pending=%d", len(bus.published), delivery.retried, delivery.acked, len(pending))
	}
}

func gatewayDrainCommand(now time.Time) *agentv1.DrainCommand {
	commandID := uuid.NewString()
	plan := []byte(`{"drain":"canonical"}`)
	digest := sha256.Sum256(plan)
	return &agentv1.DrainCommand{Event: &commonv1.EventMetadata{
		EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now), TaskId: &commandID,
	}, Schema: agentv1.DrainSchema_DRAIN_SCHEMA_V1, CommandId: commandID, NodeId: uuid.NewString(),
		PlanId: "l4-plan", Revision: 7, CanonicalPlanJson: plan, PlanSha256: digest[:], DeadlineTime: timestamppb.New(now.Add(time.Hour))}
}

func gatewayDrainStatus(command *agentv1.DrainCommand, at time.Time, phase agentv1.DrainPhase, pending bool, errorCode string) *agentv1.DrainStatus {
	causationID := command.Event.EventId
	taskID := command.CommandId
	return &agentv1.DrainStatus{Event: &commonv1.EventMetadata{
		EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.New(at), CausationId: &causationID, TaskId: &taskID,
	}, Schema: command.Schema, CommandId: command.CommandId, NodeId: command.NodeId, PlanId: command.PlanId,
		Revision: command.Revision, PlanSha256: command.PlanSha256, Phase: phase, StatusRevision: uint64(at.Unix()),
		Pending: pending, Degraded: phase == agentv1.DrainPhase_DRAIN_PHASE_ROLLED_BACK || phase == agentv1.DrainPhase_DRAIN_PHASE_FAILED,
		ErrorCode: errorCode}
}
