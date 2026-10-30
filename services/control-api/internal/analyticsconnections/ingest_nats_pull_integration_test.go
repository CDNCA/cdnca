package analyticsconnections

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSSubscriberPullFetchWaitsForBrokerTimeout(t *testing.T) {
	natsURL := strings.TrimSpace(os.Getenv("ANALYTICS_CONNECTIONS_TEST_NATS_URL"))
	if natsURL == "" {
		t.Skip("ANALYTICS_CONNECTIONS_TEST_NATS_URL is not set")
	}

	connection, err := nats.Connect(natsURL, nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatalf("connect NATS: %v", err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatalf("open JetStream: %v", err)
	}

	suffix := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano())
	stream := "CONNECTIONS_PULL_PROOF_" + suffix
	durable := "connections_pull_proof_" + suffix
	if _, err := jetstream.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{ConnectionsSubject}, Storage: nats.MemoryStorage,
	}); err != nil {
		t.Fatalf("add stream: %v", err)
	}
	t.Cleanup(func() { _ = jetstream.DeleteStream(stream) })
	if _, err := jetstream.AddConsumer(stream, &nats.ConsumerConfig{
		Durable: durable, AckPolicy: nats.AckExplicitPolicy, MaxDeliver: 2,
		FilterSubject: ConnectionsSubject,
	}); err != nil {
		t.Fatalf("add consumer: %v", err)
	}

	config := RuntimeConfig{
		Enabled: true, NATSURL: natsURL, Stream: stream, Durable: durable, Subject: ConnectionsSubject,
		Endpoint: "http://127.0.0.1:8123", Database: "cdnca_analytics",
		ConnectTimeout: time.Second, OperationTimeout: 100 * time.Millisecond, MaxResponseBytes: 1 << 20,
	}
	subscriber, err := NewNATSSubscriber(connection, config)
	if err != nil {
		t.Fatalf("open subscriber: %v", err)
	}
	t.Cleanup(func() { _ = subscriber.Close() })

	started := time.Now()
	_, err = subscriber.Next(context.Background())
	if !errors.Is(err, ErrBrokerUnavailable) {
		t.Fatalf("empty pull fetch error = %v, want %v", err, ErrBrokerUnavailable)
	}
	if elapsed := time.Since(started); elapsed < 50*time.Millisecond {
		t.Fatalf("empty pull fetch returned before broker timeout: %v", elapsed)
	}
}
