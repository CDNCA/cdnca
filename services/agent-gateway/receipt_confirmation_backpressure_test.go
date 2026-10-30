package gateway

import (
	"context"
	"fmt"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Terminal receipt confirmations wait for two heartbeats before they are
// compacted; until then they count against MaxPendingCommands with the
// commands in flight. The gateway must not deliver a command whose terminal
// receipt it could not confirm: otherwise a burst of quick deployments (node
// artifact set segments) overflows the confirmations, the session ends with
// ResourceExhausted, and every reconnect replays the same receipts before any
// heartbeat can compact them.
func TestGatewayHoldsCommandsWhileReceiptConfirmationsAreFull(t *testing.T) {
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	bus := newTestTerminalReceiptBus(store)
	gateway := newCommandGateway(t, defaultFakeControl(), bus, func(config *Config) { config.MaxPendingCommands = 2 })
	commands := make([]*agentv1.DeploymentCommand, 3)
	for index := range commands {
		command := validDeploymentCommand()
		command.ConfigVersionId = uuid.NewString()
		command.Event.Traceparent = "00-11111111111111111111111111111111-2222222222222222-01"
		command.Event.TaskId = proto.String(fmt.Sprintf("backpressure-%d", index))
		commands[index] = command
		bus.subscription.deliveries <- &testTerminalReceiptDelivery{
			fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: fmt.Sprintf("stream:%d", 100+index),
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lease, err := NewMemorySessionCoordinator().Acquire(ctx, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 8)}
	received := make(chan connectReceive, 8)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false, false, true, true,
		)
	}()
	next := func(what string) *agentv1.ConnectResponse {
		t.Helper()
		select {
		case response := <-stream.sent:
			return response
		case err := <-done:
			t.Fatalf("session ended waiting for %s: %v", what, err)
		case <-time.After(2 * time.Second):
			t.Fatalf("no %s", what)
		}
		return nil
	}
	sequence := uint64(1)
	send := func(request *agentv1.ConnectRequest) {
		sequence++
		request.Stream = &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()}
		received <- connectReceive{request: request}
	}
	// finish reports the command failed and confirms the gateway's ACK (what
	// the Agent does once its acknowledgement receipt is durable).
	finish := func(command *agentv1.DeploymentCommand) {
		t.Helper()
		send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_DeploymentStatus{
			DeploymentStatus: terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)}})
		ack := next("deployment status ACK").GetDeploymentStatusAck()
		if ack == nil || ack.DeploymentId != command.DeploymentId {
			t.Fatalf("deployment status ACK = %+v, want %s", ack, command.DeploymentId)
		}
		send(&agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_DeploymentStatusAckReceipt{
			DeploymentStatusAckReceipt: &agentv1.DeploymentStatusAckReceipt{
				StatusEventId: ack.StatusEventId, DeploymentId: ack.DeploymentId, Attempt: ack.Attempt,
				ConfigVersionId: ack.ConfigVersionId, TransitionSequence: ack.TransitionSequence,
				PersistedTime:   timestamppb.New(ack.PersistedTime.AsTime()),
				PublishedStream: ack.PublishedStream, PublishedSequence: ack.PublishedSequence,
			}}})
	}
	for index := range 2 {
		if got := next("command").GetDeploymentCommand(); got.GetDeploymentId() != commands[index].DeploymentId {
			t.Fatalf("command %d = %+v", index, got)
		}
	}
	finish(commands[0])
	waitForTest(t, time.Second, func() bool { return store.confirmedCount() == 1 })
	// One command in flight and one confirmation waiting: the limit is reached.
	select {
	case response := <-stream.sent:
		t.Fatalf("command delivered beyond the confirmation limit: %+v", response)
	case err := <-done:
		t.Fatalf("session ended: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	finish(commands[1])
	waitForTest(t, time.Second, func() bool { return store.confirmedCount() == 2 })

	// Two causal heartbeats compact both confirmations; the held command follows.
	causation := ""
	for index := range 2 {
		heartbeat := validHeartbeatRequest(lease.Epoch(), uint64(index+1), sequence+1, uuid.NewString(), uuid.NewString())
		heartbeat.GetHeartbeat().ActiveConfigIdentityCapability = testActiveIdentityCapability()
		if causation != "" {
			heartbeat.GetHeartbeat().Event.CausationId = proto.String(causation)
		}
		causation = heartbeat.GetHeartbeat().Event.EventId
		send(heartbeat)
		if next("heartbeat ACK").GetHeartbeatAck() == nil {
			t.Fatal("heartbeat was not acknowledged first")
		}
	}
	waitForTest(t, time.Second, func() bool { return store.confirmedCount() == 0 })
	if got := next("held command").GetDeploymentCommand(); got.GetDeploymentId() != commands[2].DeploymentId {
		t.Fatalf("held command = %+v", got)
	}
	finish(commands[2])
	waitForTest(t, time.Second, func() bool { return store.confirmedCount() == 1 })
	select {
	case err := <-done:
		t.Fatalf("session ended after the held command: %v", err)
	default:
	}
}
