package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/nats-io/nats.go"
)

func TestLoadBootstrapConfigRejectsCredentialAndTransportDrift(t *testing.T) {
	environment := map[string]string{
		"DATABASE_URL":                   "postgres://database.example.test/control",
		"CONTROL_INSTALLATION_ID":        "70000000-0000-4000-8000-000000000001",
		"ANALYTICS_INGEST_NATS_URL":      "tls://nats.example.test:4222",
		"ANALYTICS_INGEST_NATS_USER":     "runtime",
		"ANALYTICS_INGEST_NATS_PASSWORD": "protected-value",
	}
	lookup := func(name string) (string, bool) { value, ok := environment[name]; return value, ok }
	config, err := loadBootstrapConfig(lookup)
	if err != nil || config.Stream != "ANALYTICS_INGEST_V1" ||
		config.Durable != "control_api_analytics_ingest_v1" || config.OperationTimeout != 5*time.Second {
		t.Fatalf("default config = %#v, %v", config, err)
	}
	for _, invalid := range []string{"nats://nats.example.test:4222", "tls://user:secret@nats.example.test:4222"} {
		environment["ANALYTICS_INGEST_NATS_URL"] = invalid
		if _, err := loadBootstrapConfig(lookup); !errors.Is(err, errInvalidConfig) {
			t.Fatalf("invalid NATS URL %q error = %v", invalid, err)
		}
	}
	environment["ANALYTICS_INGEST_NATS_URL"] = "tls://nats.example.test:4222"
	environment["ANALYTICS_INGEST_NATS_USER"] = ""
	if _, err := loadBootstrapConfig(lookup); !errors.Is(err, errInvalidConfig) ||
		err != nil && strings.Contains(err.Error(), environment["ANALYTICS_INGEST_NATS_PASSWORD"]) {
		t.Fatalf("unpaired credential error = %v", err)
	}
}

func TestGenerationFromBrokerAcceptsOnlyPristineHistory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	streamCreated := now.Add(-2 * time.Second)
	consumerCreated := now.Add(-time.Second)
	config := bootstrapConfig{
		InstallationID: "70000000-0000-4000-8000-000000000001",
		Stream:         "ANALYTICS_INGEST_V1", Durable: "control_api_analytics_ingest_v1",
	}
	stream := &nats.StreamInfo{
		Config: nats.StreamConfig{Name: config.Stream}, Created: streamCreated,
		State: nats.StreamState{Msgs: 2, FirstSeq: 1, LastSeq: 2, Consumers: 1},
	}
	consumer := &nats.ConsumerInfo{
		Stream: config.Stream, Name: config.Durable, Created: consumerCreated,
		Config: nats.ConsumerConfig{
			Durable: config.Durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
			FilterSubject: analytics.IngestSubjectPrefix + ".*",
		},
		NumPending: 2,
	}
	bootstrap, err := generationFromBroker(config, stream, consumer, now)
	if err != nil || bootstrap.Generation.StreamCreatedUnixNano != uint64(streamCreated.UnixNano()) ||
		bootstrap.Generation.ConsumerCreatedUnixNano != uint64(consumerCreated.UnixNano()) ||
		bootstrap.Generation.HistoryStartSequence != 1 || bootstrap.HistoryStartAt != consumerCreated {
		t.Fatalf("pristine generation = %#v, %v", bootstrap, err)
	}

	checks := []func(){
		func() { stream.State.FirstSeq = 2 },
		func() { stream.State.NumDeleted = 1 },
		func() { consumer.Delivered.Stream = 1 },
		func() { consumer.AckFloor.Consumer = 1 },
		func() { consumer.NumPending = 1 },
	}
	for index, mutate := range checks {
		streamCopy, consumerCopy := *stream, *consumer
		stream, consumer = &streamCopy, &consumerCopy
		stream.State.FirstSeq, stream.State.NumDeleted = 1, 0
		consumer.Delivered, consumer.AckFloor = nats.SequenceInfo{}, nats.SequenceInfo{}
		consumer.NumPending = 2
		mutate()
		if _, err := generationFromBroker(config, stream, consumer, now); !errors.Is(err, errUnsafeBroker) {
			t.Fatalf("unsafe broker case %d error = %v", index, err)
		}
	}
}
