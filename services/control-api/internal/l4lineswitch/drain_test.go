package l4lineswitch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/l4drain"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type drainPlanSourceStub struct {
	plans map[uuid.UUID]l4drain.Plan
}

func (source drainPlanSourceStub) Plans(context.Context, Actor, Switch) (map[uuid.UUID]l4drain.Plan, error) {
	return source.plans, nil
}

type drainStatusJetStreamStub struct {
	nats.JetStreamContext
	subjects map[string]uint64
	messages map[string]*nats.RawStreamMsg
}

func (stub *drainStatusJetStreamStub) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) {
	return &nats.StreamInfo{State: nats.StreamState{Subjects: stub.subjects}}, nil
}

func (stub *drainStatusJetStreamStub) GetLastMsg(_ string, subject string, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	message := stub.messages[subject]
	if message == nil {
		return nil, nats.ErrMsgNotFound
	}
	return message, nil
}

func TestDrainCommandsRemainByteIdenticalAcrossRestart(t *testing.T) {
	value, nodeID, plan := drainFixture()
	now := value.UpdatedAt
	coordinator := &JetStreamDrainCoordinator{
		plans: drainPlanSourceStub{plans: map[uuid.UUID]l4drain.Plan{nodeID: plan}},
		now:   func() time.Time { return now },
	}
	first, err := coordinator.Build(t.Context(), ReconcilerActor(), value)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Minute)
	value.UpdatedAt = now
	second, err := coordinator.Build(t.Context(), ReconcilerActor(), value)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(first[nodeID], second[nodeID]) {
		t.Fatalf("replayed command bytes drifted\nfirst=%v\nsecond=%v", first[nodeID], second[nodeID])
	}
}

func TestDrainStatusUsesGatewaySubjectAndExactPlanFence(t *testing.T) {
	value, nodeID, plan := drainFixture()
	coordinator := &JetStreamDrainCoordinator{
		plans:  drainPlanSourceStub{plans: map[uuid.UUID]l4drain.Plan{nodeID: plan}},
		config: DefaultJetStreamDrainConfig(), now: func() time.Time { return value.UpdatedAt },
	}
	commands, err := coordinator.Build(t.Context(), ReconcilerActor(), value)
	if err != nil {
		t.Fatal(err)
	}
	command := commands[nodeID]
	completed := drainStatusFixture(command, 5, agentv1.DrainPhase_DRAIN_PHASE_COMPLETED, false)
	unrelated := proto.Clone(completed).(*agentv1.DrainStatus)
	unrelated.CommandId = uuid.NewString()
	stub := &drainStatusJetStreamStub{subjects: map[string]uint64{}, messages: map[string]*nats.RawStreamMsg{}}
	putDrainStatus(t, stub, coordinator.config.StatusPrefix, unrelated)
	putDrainStatus(t, stub, coordinator.config.StatusPrefix, completed)
	coordinator.js = stub
	status, err := coordinator.Status(t.Context(), ReconcilerActor(), command)
	if err != nil || status != DrainCompleted {
		t.Fatalf("status=%q error=%v", status, err)
	}

	forged := proto.Clone(completed).(*agentv1.DrainStatus)
	forged.StatusRevision = 6
	forged.PlanSha256 = bytes.Repeat([]byte{0x99}, 32)
	putDrainStatus(t, stub, coordinator.config.StatusPrefix, forged)
	if _, err := coordinator.Status(t.Context(), ReconcilerActor(), command); !errors.Is(err, ErrConflict) {
		t.Fatalf("forged plan error=%v", err)
	}
}

func TestDrainStatusIgnoresLateTerminalEvidenceWhenNewerProgressIsPending(t *testing.T) {
	value, nodeID, plan := drainFixture()
	coordinator := &JetStreamDrainCoordinator{
		plans:  drainPlanSourceStub{plans: map[uuid.UUID]l4drain.Plan{nodeID: plan}},
		config: DefaultJetStreamDrainConfig(), now: func() time.Time { return value.UpdatedAt },
	}
	commands, err := coordinator.Build(t.Context(), ReconcilerActor(), value)
	if err != nil {
		t.Fatal(err)
	}
	stub := &drainStatusJetStreamStub{subjects: map[string]uint64{}, messages: map[string]*nats.RawStreamMsg{}}
	putDrainStatus(t, stub, coordinator.config.StatusPrefix,
		drainStatusFixture(commands[nodeID], 2, agentv1.DrainPhase_DRAIN_PHASE_COMPLETED, false))
	putDrainStatus(t, stub, coordinator.config.StatusPrefix,
		drainStatusFixture(commands[nodeID], 3, agentv1.DrainPhase_DRAIN_PHASE_DRAINING_OLD, true))
	coordinator.js = stub
	status, err := coordinator.Status(t.Context(), ReconcilerActor(), commands[nodeID])
	if err != nil || status != DrainPending {
		t.Fatalf("status=%q error=%v", status, err)
	}
}

func drainFixture() (Switch, uuid.UUID, l4drain.Plan) {
	nodeID := uuid.New()
	value := Switch{
		ID: uuid.New(), ConfigurationScopeID: uuid.New(), ExpectedSourceRevision: 19,
		RequestID: uuid.New(), CorrelationID: uuid.New(), Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
		Deadline: time.Date(2026, 8, 8, 4, 0, 0, 0, time.UTC), CreatedAt: time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC),
		UpdatedAt:     time.Date(2026, 8, 8, 3, 30, 0, 0, time.UTC),
		RetiringNodes: []uuid.UUID{nodeID}, DrainCommands: map[uuid.UUID]uuid.UUID{nodeID: uuid.NewSHA1(uuid.Nil, nodeID[:])},
	}
	value.DrainCommands[nodeID] = uuid.NewSHA1(value.ID, nodeID[:])
	plan := l4drain.Plan{
		SchemaVersion: l4drain.SchemaVersionV1, PlanID: uuid.NewSHA1(value.ID, []byte("plan")).String(), Revision: 7,
		Old: l4drain.Version{VersionID: uuid.NewString(), Listeners: []l4drain.Listener{{
			ID: "tcp.v4", Protocol: "tcp", Address: "0.0.0.0", Port: 443,
			UpstreamAddress: "192.0.2.10", UpstreamPort: 8443,
		}}},
		New:                  l4drain.Version{VersionID: uuid.NewString(), Listeners: []l4drain.Listener{}},
		HealthTimeoutSeconds: 30, HealthChecks: []l4drain.HealthCheck{},
		Drain: l4drain.DrainPolicy{MaxDrainSeconds: 600, Force: "never"},
	}
	return value, nodeID, plan
}

func drainStatusFixture(command *agentv1.DrainCommand, revision uint64, phase agentv1.DrainPhase, pending bool) *agentv1.DrainStatus {
	event := proto.Clone(command.Event).(*commonv1.EventMetadata)
	event.EventId = uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("status:%s:%d", command.CommandId, revision))).String()
	causationID, taskID := command.Event.EventId, command.CommandId
	event.CausationId, event.TaskId = &causationID, &taskID
	return &agentv1.DrainStatus{
		Event:  event,
		Schema: command.Schema, CommandId: command.CommandId, NodeId: command.NodeId,
		PlanId: command.PlanId, Revision: command.Revision, PlanSha256: append([]byte(nil), command.PlanSha256...),
		Phase: phase, StatusRevision: revision, Pending: pending,
	}
}

func putDrainStatus(t *testing.T, stub *drainStatusJetStreamStub, prefix string, status *agentv1.DrainStatus) {
	t.Helper()
	subject := prefix + "." + status.NodeId + "_" + status.CommandId + "_" + fmt.Sprint(status.StatusRevision)
	encoded, err := proto.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	stub.subjects[subject] = 1
	stub.messages[subject] = &nats.RawStreamMsg{Subject: subject, Sequence: status.StatusRevision, Data: encoded}
}
