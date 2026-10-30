package gatewayclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/drainruntime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type recordingDrainHandler struct {
	result drainruntime.Result
	err    error
	plan   drainruntime.Plan
}

func (handler *recordingDrainHandler) HandleDrainPlan(_ context.Context, plan drainruntime.Plan) (drainruntime.Result, error) {
	handler.plan = plan
	return handler.result, handler.err
}

func TestDrainCommandRejectsNonCanonicalCarrierAndMapsDurableProgress(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	command := testDrainCommand(t, now)
	config := DefaultConfig()
	config.NodeID = command.NodeId

	nonCanonical := proto.Clone(command).(*agentv1.DrainCommand)
	nonCanonical.CanonicalPlanJson = append(nonCanonical.CanonicalPlanJson, ' ')
	digest := sha256.Sum256(nonCanonical.CanonicalPlanJson)
	nonCanonical.PlanSha256 = digest[:]
	if _, _, err := validateDrainCommand(nonCanonical, config, now); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("noncanonical command error = %v", err)
	}

	handler := &recordingDrainHandler{result: drainruntime.Result{
		PlanID: command.PlanId, Revision: command.Revision, Phase: drainruntime.PhaseHealthGate,
		Transitions: []drainruntime.Transition{{Sequence: 1, Phase: drainruntime.PhaseHealthGate, At: now.Add(time.Second)}},
	}, err: drainruntime.ErrHealthPending}
	client := &Client{config: config, drain: handler, now: func() time.Time { return now }}
	status, err := client.dispatchDrainCommand(t.Context(), command)
	if err != nil || handler.plan.PlanID != command.PlanId || status.Phase != agentv1.DrainPhase_DRAIN_PHASE_HEALTH_GATE ||
		!status.Pending || status.Degraded || status.ErrorCode != "HEALTH_PENDING" || status.StatusRevision != 1 {
		t.Fatalf("pending drain status = %+v, error = %v, plan = %+v", status, err, handler.plan)
	}

	handler.result.Phase = drainruntime.PhaseCompleted
	handler.result.Transitions = append(handler.result.Transitions,
		drainruntime.Transition{Sequence: 2, Phase: drainruntime.PhaseCompleted, At: now.Add(2 * time.Second)})
	handler.err = nil
	status, err = client.dispatchDrainCommand(t.Context(), command)
	if err != nil || status.Phase != agentv1.DrainPhase_DRAIN_PHASE_COMPLETED || status.Pending || status.Degraded || status.ErrorCode != "" {
		t.Fatalf("completed drain status = %+v, error = %v", status, err)
	}

	handler.result.Phase = drainruntime.PhasePrecheck
	handler.err = errors.New("runtime unavailable")
	status, err = client.dispatchDrainCommand(t.Context(), command)
	if err != nil || status.Phase != agentv1.DrainPhase_DRAIN_PHASE_FAILED || status.Pending || !status.Degraded || status.ErrorCode != "DRAIN_RUNTIME_FAILED" {
		t.Fatalf("failed drain status = %+v, error = %v", status, err)
	}
}

func TestDrainObservationFailureStaysPendingUntilSameCommandRecovers(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	command := testDrainCommand(t, now)
	handler := &recordingDrainHandler{result: drainruntime.Result{
		PlanID: command.PlanId, Revision: command.Revision, Phase: drainruntime.PhaseDrainingOld,
		RemainingOldWorkers: 3,
		Transitions: []drainruntime.Transition{
			{Sequence: 1, Phase: drainruntime.PhaseHealthGate, At: now},
			{Sequence: 2, Phase: drainruntime.PhaseDrainingOld, At: now.Add(time.Second)},
		},
	}, err: drainruntime.ErrDrainObservationFailed}

	status, err := HandleDrainCommand(t.Context(), handler, command, command.NodeId, 1<<20, now)
	if err != nil || status.Phase != agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD || !status.Pending ||
		!status.Degraded || status.RemainingOldWorkers != 3 || status.ErrorCode != "DRAIN_OBSERVATION_FAILED" {
		t.Fatalf("observation failure status = (%+v, %v)", status, err)
	}

	handler.err = drainruntime.ErrDrainInProgress
	status, err = HandleDrainCommand(t.Context(), handler, command, command.NodeId, 1<<20, now)
	if err != nil || status.Phase != agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD || !status.Pending ||
		status.Degraded || status.ErrorCode != "DRAIN_IN_PROGRESS" {
		t.Fatalf("recovered pending status = (%+v, %v)", status, err)
	}

	handler.result.Phase = drainruntime.PhaseCompleted
	handler.result.RemainingOldWorkers = 0
	handler.result.Transitions = append(handler.result.Transitions,
		drainruntime.Transition{Sequence: 3, Phase: drainruntime.PhaseCompleted, At: now.Add(2 * time.Second)})
	handler.err = nil
	status, err = HandleDrainCommand(t.Context(), handler, command, command.NodeId, 1<<20, now)
	if err != nil || status.Phase != agentv1.DrainPhase_DRAIN_PHASE_COMPLETED || status.Pending ||
		status.Degraded || status.ErrorCode != "" {
		t.Fatalf("recovered completed status = (%+v, %v)", status, err)
	}
}

func TestDrainCapabilityNegotiationFailsClosed(t *testing.T) {
	local := &agentv1.AgentCapabilities{Features: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL, ApiVersion: 1,
	}}}
	gateway := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL, ApiVersion: 1,
	}}}
	if enabled, err := negotiateDrainControlV1(gateway, local); err != nil || !enabled {
		t.Fatalf("negotiated = %v, error = %v", enabled, err)
	}
	if enabled, err := negotiateDrainControlV1(gateway, &agentv1.AgentCapabilities{}); err == nil || enabled {
		t.Fatalf("unadvertised negotiated = %v, error = %v", enabled, err)
	}
}

func testDrainCommand(t *testing.T, now time.Time) *agentv1.DrainCommand {
	t.Helper()
	plan := drainruntime.Plan{
		SchemaVersion: drainruntime.SchemaVersionV1, PlanID: "l4-plan", Revision: 7,
		Old: drainruntime.Version{VersionID: "old-v1", Listeners: []drainruntime.Listener{{
			ID: "tcp", Protocol: drainruntime.ProtocolTCP, Address: "127.0.0.1", Port: 18080,
			UpstreamAddress: "127.0.0.1", UpstreamPort: 19080,
		}}},
		New: drainruntime.Version{VersionID: "new-v1", Listeners: []drainruntime.Listener{{
			ID: "tcp", Protocol: drainruntime.ProtocolTCP, Address: "127.0.0.1", Port: 18080,
			UpstreamAddress: "127.0.0.1", UpstreamPort: 19081,
		}}},
		HealthTimeoutSeconds: 10,
		HealthChecks:         []drainruntime.HealthCheck{{ListenerID: "tcp", Payload: "ping", ExpectedBodyPrefix: "pong"}},
		Drain:                drainruntime.DrainPolicy{MaxDrainSeconds: 60, Force: drainruntime.ForceNever},
	}
	compiled, err := drainruntime.Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(compiled.CanonicalJSON)
	commandID := uuid.NewString()
	return &agentv1.DrainCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now), TaskId: &commandID},
		Schema: agentv1.DrainSchema_DRAIN_SCHEMA_V1, CommandId: commandID, NodeId: uuid.NewString(),
		PlanId: plan.PlanID, Revision: plan.Revision, CanonicalPlanJson: compiled.CanonicalJSON, PlanSha256: digest[:],
		DeadlineTime: timestamppb.New(now.Add(time.Hour)),
	}
}
