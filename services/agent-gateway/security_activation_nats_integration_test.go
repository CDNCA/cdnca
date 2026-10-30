//go:build integration

package gateway

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func TestSecurityActivationCommandIsDurableBeforeACKAndRedeliversAfterGatewayCrash(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	commandStream := "SECURITY_COMMANDS_" + suffix
	statusStream := "SECURITY_STATUS_" + suffix
	commandPrefix := "cdnca.test." + suffix + ".commands"
	statusPrefix := "cdnca.test." + suffix + ".status"

	first := connectIntegrationNATS(t, natsURL)
	second := connectIntegrationNATS(t, natsURL)
	defer second.Close()
	js, err := second.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []*nats.StreamConfig{
		{Name: commandStream, Subjects: []string{commandPrefix + ".>"}, Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage},
		{Name: statusStream, Subjects: []string{statusPrefix + ".>"}, Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Duplicates: time.Minute},
	} {
		if _, err := js.AddStream(stream); err != nil {
			t.Fatal(err)
		}
		streamName := stream.Name
		t.Cleanup(func() { _ = js.DeleteStream(streamName) })
	}
	config := DefaultNATSCommandBusConfig()
	config.CommandStream, config.StatusStream = commandStream, statusStream
	config.CommandSubjectPrefix, config.StatusSubjectPrefix = commandPrefix, statusPrefix
	config.ConsumerPrefix = "security_" + suffix
	config.AckWait = 200 * time.Millisecond
	config.OperationTimeout = time.Second
	firstBus, err := NewNATSCommandBus(first, config)
	if err != nil {
		t.Fatal(err)
	}
	command := validDeploymentCommand()
	command.RequiredCapabilities = append(command.RequiredCapabilities, &agentv1.Capability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 1,
	})
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(commandPrefix+"."+testNodeID, payload, nats.MsgId(command.Event.EventId)); err != nil {
		t.Fatal(err)
	}
	firstSubscription, err := firstBus.Subscribe(t.Context(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	firstDelivery := nextIntegrationCommand(t, firstSubscription)
	if !proto.Equal(firstDelivery.Command(), command) {
		t.Fatal("first security command changed")
	}

	// Simulate process loss before ACK by dropping the owning NATS connection.
	first.Close()
	secondBus, err := NewNATSCommandBus(second, config)
	if err != nil {
		t.Fatal(err)
	}
	secondSubscription, err := secondBus.Subscribe(t.Context(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer secondSubscription.Close()
	redelivered := nextIntegrationCommand(t, secondSubscription)
	if !proto.Equal(redelivered.Command(), command) {
		t.Fatal("redelivered security command changed")
	}

	status := validDeploymentStatus(command)
	if _, err := secondBus.PublishStatus(context.Background(), testNodeID, status); err != nil {
		t.Fatal(err)
	}
	info, err := js.StreamInfo(statusStream)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("status durability before ACK = %+v, %v", info, err)
	}
	if err := redelivered.Ack(context.Background()); err != nil {
		t.Fatal(err)
	}
	durable := config.ConsumerPrefix + "_" + strings.ReplaceAll(testNodeID, "-", "_")
	eventually(t, time.Second, func() bool {
		consumer, err := js.ConsumerInfo(commandStream, durable)
		return err == nil && consumer.NumAckPending == 0 && consumer.NumPending == 0
	}, "security command remained pending after durable status and ACK")
}
