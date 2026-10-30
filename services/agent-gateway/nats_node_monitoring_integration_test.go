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

func TestNATSNodeMonitoringNextWaitsAcrossEmptyFetch(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	commandStream := "NODE_MONITORING_COMMANDS_" + suffix
	statusStream := "NODE_MONITORING_STATUS_" + suffix
	commandPrefix := "cdnca.test.node-monitoring." + suffix + ".commands"
	statusPrefix := "cdnca.test.node-monitoring." + suffix + ".status"
	nodeID := "01990000-0000-7000-8000-000000000007"

	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: commandStream, Subjects: []string{commandPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(commandStream) }()
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: statusStream, Subjects: []string{statusPrefix + ".*"},
		Retention: nats.LimitsPolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(statusStream) }()

	config := DefaultNATSNodeMonitoringBusConfig()
	config.CommandStream = commandStream
	config.StatusStream = statusStream
	config.CommandSubjectPrefix = commandPrefix
	config.StatusSubjectPrefix = statusPrefix
	config.ConsumerPrefix = "node_monitoring_" + suffix
	config.OperationTimeout = 100 * time.Millisecond
	bus, err := NewNATSNodeMonitoringBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	subscription, err := bus.SubscribeNodeMonitoring(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()

	type result struct {
		delivery NodeMonitoringDelivery
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		delivery, nextErr := subscription.Next(ctx)
		resultCh <- result{delivery: delivery, err: nextErr}
	}()

	select {
	case got := <-resultCh:
		t.Fatalf("Next returned before an artifact was published: delivery=%v err=%v", got.delivery != nil, got.err)
	case <-time.After(250 * time.Millisecond):
	}

	payload, err := proto.Marshal(&agentv1.NodeMonitoringArtifact{
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(commandPrefix+"."+nodeID, payload, nats.ExpectStream(commandStream), nats.MsgId(uuid.NewString())); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-resultCh:
		if got.err != nil || got.delivery == nil {
			t.Fatalf("Next after delayed artifact = delivery=%v err=%v", got.delivery != nil, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Next did not return after an artifact was published")
	}
}

// A rejected revision is redelivered after a delay without blocking a newer
// revision for the same node, so fixing a bad override takes effect.
func TestNATSNodeMonitoringDelayedRejectionDoesNotBlockNewerRevision(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	commandStream := "NODE_MONITORING_COMMANDS_" + suffix
	commandPrefix := "cdnca.test.node-monitoring." + suffix + ".commands"
	statusStream := "NODE_MONITORING_STATUS_" + suffix
	statusPrefix := "cdnca.test.node-monitoring." + suffix + ".status"
	nodeID := "01990000-0000-7000-8000-000000000008"
	connection := connectIntegrationNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []*nats.StreamConfig{
		{Name: commandStream, Subjects: []string{commandPrefix + ".*"}, Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage},
		{Name: statusStream, Subjects: []string{statusPrefix + ".*"}, Retention: nats.LimitsPolicy, Storage: nats.FileStorage},
	} {
		if _, err := js.AddStream(stream); err != nil {
			t.Fatal(err)
		}
		name := stream.Name
		defer func() { _ = js.DeleteStream(name) }()
	}
	config := DefaultNATSNodeMonitoringBusConfig()
	config.CommandStream, config.StatusStream = commandStream, statusStream
	config.CommandSubjectPrefix, config.StatusSubjectPrefix = commandPrefix, statusPrefix
	config.ConsumerPrefix = "node_monitoring_" + suffix
	config.OperationTimeout = 200 * time.Millisecond
	bus, err := NewNATSNodeMonitoringBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []uint64{5, 6} {
		payload, err := proto.Marshal(&agentv1.NodeMonitoringArtifact{Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1,
			NodeId: nodeID, ConfigRevision: revision, PublicationSequence: revision})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := js.Publish(commandPrefix+"."+nodeID, payload, nats.ExpectStream(commandStream), nats.MsgId(uuid.NewString())); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subscription, err := bus.SubscribeNodeMonitoring(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	first, err := subscription.Next(ctx)
	if err != nil || first.Artifact().ConfigRevision != 5 {
		t.Fatalf("first delivery = %v, %v", first, err)
	}
	if err := first.NakWithDelay(ctx, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	second, err := subscription.Next(ctx)
	if err != nil || second.Artifact().ConfigRevision != 6 {
		t.Fatalf("delayed rejection blocked the newer revision: %v, %v", second, err)
	}
	if err := second.Ack(ctx); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	redelivered, err := subscription.Next(ctx)
	if err != nil || redelivered.Artifact().ConfigRevision != 5 || time.Since(started) < time.Second {
		t.Fatalf("rejected revision redelivery = %v after %s, %v", redelivered, time.Since(started), err)
	}
}
