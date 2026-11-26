//go:build integration

package gateway

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// A session that ends (the Agent reconnected, or a status could not be
// persisted) with a delivered, unacknowledged command and a pull still waiting
// at the server must hand that command to the next session at once. Naking it
// while this session's pull subscription still had interest made the server
// redeliver it into that pull, the subscription was then closed and the
// command came back only after AckWait (2 minutes in production): the next
// sessions had no authoritative command for the Agent's replayed terminal
// status and were refused until then.
func TestJetStreamSessionStopRedeliversInFlightCommandToNextSession(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	busConfig := DefaultNATSCommandBusConfig()
	busConfig.CommandStream = "AGENT_COMMANDS_" + suffix
	busConfig.StatusStream = "AGENT_STATUS_" + suffix
	busConfig.CommandSubjectPrefix = "cdnca.test." + suffix + ".commands"
	busConfig.StatusSubjectPrefix = "cdnca.test." + suffix + ".status"
	busConfig.ConsumerPrefix = "node_" + suffix
	busConfig.AckWait = 20 * time.Second
	busConfig.OperationTimeout = 5 * time.Second
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: busConfig.CommandStream, Subjects: []string{busConfig.CommandSubjectPrefix + ".>"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(busConfig.CommandStream) }()
	bus, err := NewNATSCommandBus(connection, busConfig)
	if err != nil {
		t.Fatal(err)
	}
	command := validRollbackDeploymentCommand()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(busConfig.CommandSubjectPrefix+"."+testNodeID, payload, nats.MsgId(command.Event.EventId)); err != nil {
		t.Fatal(err)
	}

	streamCtx, closeStream := context.WithCancel(context.Background())
	source, err := newSessionCommandSource(streamCtx, bus, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	source.arm()
	var received commandReceive
	select {
	case received = <-source.next:
	case <-time.After(2 * time.Second):
		t.Fatal("first session did not receive the command")
	}
	if received.err != nil {
		t.Fatal(received.err)
	}
	source.next = nil
	pending := pendingCommandSet{commandKey(received.delivery.Command()): {
		command: received.delivery.Command(), deliveries: []CommandDelivery{received.delivery},
	}}
	// The session loop re-arms the next pull while the command is in flight.
	source.arm()
	time.Sleep(100 * time.Millisecond)
	// The Agent closes the stream: the waiting Fetch returns, its pull request
	// stays at the server until it expires.
	closeStream()
	time.Sleep(50 * time.Millisecond)
	stopSessionCommands(source, pending, time.Second)

	nextSource, err := newSessionCommandSource(context.Background(), bus, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer stopSessionCommands(nextSource, pendingCommandSet{}, time.Second)
	nextSource.arm()
	select {
	case redelivered := <-nextSource.next:
		nextSource.next = nil
		if redelivered.err != nil {
			t.Fatal(redelivered.err)
		}
		if !proto.Equal(redelivered.delivery.Command(), command) {
			t.Fatalf("redelivered command changed: %+v", redelivered.delivery.Command())
		}
		if err := redelivered.delivery.Ack(context.Background()); err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight command was not redelivered to the next session; it waits for AckWait")
	}
}
