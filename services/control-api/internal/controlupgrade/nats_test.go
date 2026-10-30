package controlupgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestCommandBusPublishesExactStableWire(t *testing.T) {
	payload := []byte(`{"schema":"cdnca.edge.upgrade.command/v1","command_id":"00000000-0000-4000-8000-000000000001"}`)
	jetstream := &upgradeJetStreamStub{ack: &nats.PubAck{Stream: "AGENT_COMMANDS", Sequence: 17, Duplicate: true}}
	bus, err := NewCommandBus(jetstream, "AGENT_COMMANDS")
	if err != nil {
		t.Fatal(err)
	}
	result, err := bus.Publish(context.Background(), RolloutOutboxMessage{
		ID:         "00000000-0000-4000-8000-000000000001",
		Topic:      "cdnca.agent.commands.upgrade.00000000-0000-4000-8000-000000000002",
		MessageKey: "00000000-0000-4000-8000-000000000001", PayloadBytes: payload,
		PayloadSHA256: rolloutWireDigest(payload),
	})
	if err != nil || result.Stream != "AGENT_COMMANDS" || result.Sequence != 17 || !result.Duplicate {
		t.Fatalf("Publish() = (%#v,%v)", result, err)
	}
	if jetstream.message == nil || jetstream.message.Subject != "cdnca.agent.commands.upgrade.00000000-0000-4000-8000-000000000002" ||
		!bytes.Equal(jetstream.message.Data, payload) ||
		jetstream.message.Header.Get(nats.MsgIdHdr) != commandMessageID(payload) ||
		jetstream.message.Header.Get(nats.ExpectedStreamHdr) != "AGENT_COMMANDS" ||
		jetstream.message.Header.Get("X-CDNCA-Payload-SHA256") != rolloutWireDigest(payload) {
		t.Fatalf("published command wire = %#v", jetstream.message)
	}
	if jetstream.message.Header.Get("X-CDNCA-Message-Key") != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("message key header = %q", jetstream.message.Header.Get("X-CDNCA-Message-Key"))
	}
}

func TestUpgradeStatusConsumerBindsDualFilterConsumerWithoutSubject(t *testing.T) {
	expected := expectedUpgradeStatusConsumer(DefaultStatusConsumerConfig())
	want := []string{
		"cdnca.agent.deployment-status.upgrade.*",
		"cdnca.agent.deployment-status.upgrade-v2.*",
	}
	if expected.FilterSubject != "" || len(expected.FilterSubjects) != len(want) {
		t.Fatalf("filters=(%q,%v), want empty/%v", expected.FilterSubject, expected.FilterSubjects, want)
	}
	for index := range want {
		if expected.FilterSubjects[index] != want[index] {
			t.Fatalf("filter %d=%q, want %q", index, expected.FilterSubjects[index], want[index])
		}
	}
	source, err := os.ReadFile("nats.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte(`PullSubscribe("", config.Durable`)) {
		t.Fatal("multi-filter consumer is not bound with an empty subscription subject")
	}
}

func TestUpgradeStatusConsumerMetadataRejectsNATSServerDrift(t *testing.T) {
	config := DefaultStatusConsumerConfig()
	serverMetadata := map[string]string{
		"_nats.req.level": "0",
		"_nats.level":     "1",
		"_nats.ver":       "2.11.4",
	}
	for _, test := range []struct {
		name     string
		expected map[string]string
		actual   map[string]string
		want     bool
	}{
		{name: "stub without server metadata", want: true},
		{name: "exact server metadata", actual: serverMetadata, want: true},
		{name: "user metadata remains exact", expected: map[string]string{"owner": "control"}, actual: map[string]string{
			"owner": "control", "_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.4",
		}, want: true},
		{name: "unknown reserved key", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.4", "_nats.future": "1",
		}},
		{name: "required level nonzero", actual: map[string]string{
			"_nats.req.level": "1", "_nats.level": "1", "_nats.ver": "2.11.4",
		}},
		{name: "required level noncanonical", actual: map[string]string{
			"_nats.req.level": "00", "_nats.level": "1", "_nats.ver": "2.11.4",
		}},
		{name: "server level noncanonical", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "01", "_nats.ver": "2.11.4",
		}},
		{name: "server version malformed", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11",
		}},
		// Captured from the signed native server on a fresh 1.0.25 install (2026-10-13).
		{name: "pinned native production server", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "3", "_nats.ver": "2.12.15-cdnca.1",
		}, want: true},
		{name: "native server with e2e api level", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.12.15-cdnca.1",
		}},
		{name: "e2e server with native api level", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "3", "_nats.ver": "2.11.4",
		}},
		{name: "server version wrong", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.5",
		}},
		{name: "unpatched production minor", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.12.15",
		}},
		{name: "partial server metadata", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1",
		}},
		{name: "user metadata mismatch", expected: map[string]string{"owner": "control"}, actual: map[string]string{
			"owner": "other", "_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.4",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			expected := expectedUpgradeStatusConsumer(config)
			expected.Metadata = test.expected
			actual := *expected
			actual.Metadata = test.actual
			info := &nats.ConsumerInfo{Stream: config.Stream, Name: config.Durable, Config: actual}
			if got := sameUpgradeStatusConsumer(info, config.Stream, expected); got != test.want {
				t.Fatalf("sameUpgradeStatusConsumer() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUpgradeStatusConsumerBindsNATS2114Readback(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection, err := nats.Connect(natsURL, nats.Name("control-upgrade-status-metadata-test"),
		nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	if version := connection.ConnectedServerVersion(); version != "2.11.4" {
		t.Fatalf("NATS server version = %q, want 2.11.4", version)
	}
	jetstream, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultStatusConsumerConfig()
	if _, err = jetstream.AddStream(&nats.StreamConfig{Name: config.Stream, Subjects: []string{
		upgradeStatusSubjectPrefix + ".*", upgradeStatusV2SubjectPrefix + ".*",
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jetstream.DeleteStream(config.Stream) })
	if _, err = jetstream.AddConsumer(config.Stream, expectedUpgradeStatusConsumer(config)); err != nil {
		t.Fatal(err)
	}
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable)
	if err != nil {
		t.Fatal(err)
	}
	wantServerMetadata := map[string]string{
		"_nats.req.level": "0",
		"_nats.level":     "1",
		"_nats.ver":       "2.11.4",
	}
	for key, want := range wantServerMetadata {
		if got := info.Config.Metadata[key]; got != want {
			t.Fatalf("consumer metadata[%q] = %q, want %q; metadata=%v", key, got, want, info.Config.Metadata)
		}
	}
	consumer, err := BindUpgradeStatusConsumer(jetstream, config)
	if err != nil {
		t.Fatal(err)
	}
	if err = consumer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCommandBusClassifiesUnknownAndPermanentOutcomes(t *testing.T) {
	message := RolloutOutboxMessage{ID: "00000000-0000-4000-8000-000000000001",
		Topic:        "cdnca.agent.commands.upgrade.00000000-0000-4000-8000-000000000002",
		MessageKey:   "00000000-0000-4000-8000-000000000001",
		PayloadBytes: []byte(`{"schema":"cdnca.edge.upgrade.command/v1"}`)}
	message.PayloadSHA256 = rolloutWireDigest(message.PayloadBytes)
	for _, test := range []struct {
		name string
		stub *upgradeJetStreamStub
		want error
	}{
		{"transport unknown", &upgradeJetStreamStub{err: errors.New("connection reset")}, ErrPublishOutcomeUnknown},
		{"wrong stream", &upgradeJetStreamStub{ack: &nats.PubAck{Stream: "OTHER", Sequence: 1}}, ErrPublishRejected},
		{"permanent api", &upgradeJetStreamStub{err: &nats.APIError{Code: 400, ErrorCode: 10060, Description: "stream mismatch"}}, ErrPublishRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			bus, _ := NewCommandBus(test.stub, "AGENT_COMMANDS")
			if _, err := bus.Publish(context.Background(), message); !errors.Is(err, test.want) {
				t.Fatalf("Publish() error = %v, want %v", err, test.want)
			}
		})
	}
}

type upgradeJetStreamStub struct {
	nats.JetStreamContext
	message *nats.Msg
	ack     *nats.PubAck
	err     error
}

func (stub *upgradeJetStreamStub) PublishMsg(message *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	stub.message = message
	return stub.ack, stub.err
}
