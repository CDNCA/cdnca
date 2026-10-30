//go:build integration

package nodemetrics

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSConsumerBindsPrecreatedFilteredDurable(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection, err := nats.Connect(natsURL, nats.Name("control-api-node-metrics-bind-integration"),
		nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(&nats.StreamConfig{
		Name: NodeMonitoringStatusStream, Subjects: []string{DefaultSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jetstream.DeleteStream(NodeMonitoringStatusStream) }()

	config := DefaultNATSConsumerConfig()
	if _, err := jetstream.AddConsumer(config.Stream, &nats.ConsumerConfig{
		Durable: config.Durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait, MaxDeliver: -1,
		FilterSubject: config.SubjectPrefix + ".*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: config.MaxAckPending, MaxWaiting: config.MaxWaiting,
		MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
	}); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()

	ack, err := jetstream.Publish(config.SubjectPrefix+".00000000-0000-4000-8000-000000000001", []byte("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	delivery, err := consumer.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	metadata := delivery.Metadata()
	if metadata.Stream != config.Stream || metadata.Durable != config.Durable ||
		metadata.StreamSequence != ack.Sequence || metadata.ConsumerSequence != 1 || metadata.NumDelivered != 1 {
		t.Fatalf("delivery metadata = %+v, publish ack = %+v", metadata, ack)
	}
	if err := delivery.Ack(ctx); err != nil {
		t.Fatal(err)
	}
}
