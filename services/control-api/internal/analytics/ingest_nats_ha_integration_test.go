package analytics

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

func TestOBSUsageATwoInstanceLeaseTakeoverAndStreamEpoch(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	cleanup := func() {
		_ = jetstream.DeleteConsumer(config.Stream, config.Durable)
		_ = jetstream.DeleteStream(config.Stream)
		_ = jetstream.DeleteStream(config.IsolationStream)
		for _, bucket := range obsUsageACoordinationBuckets(config) {
			_ = jetstream.DeleteKeyValue(bucket)
		}
	}
	defer cleanup()
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	first, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	event := validAccessEvent("lease-first")
	event.ConfigVersion = testConfigVersionID
	event.OccurredAt = now.Add(-time.Minute)
	publishAccessEnvelope(t, jetstream, config.Stream, "lease-first-message", now, []AccessEvent{event})
	event.EventID = "lease-second"
	publishAccessEnvelope(t, jetstream, config.Stream, "lease-second-message", now, []AccessEvent{event})

	firstDeliveries, err := first.Fetch(context.Background())
	if err != nil || len(firstDeliveries) == 0 {
		t.Fatalf("first instance did not acquire lease: deliveries=%d err=%v", len(firstDeliveries), err)
	}
	if secondDeliveries, secondErr := second.Fetch(context.Background()); !errors.Is(secondErr, ErrNoIngestMessages) || len(secondDeliveries) != 0 {
		t.Fatalf("second instance bypassed active lease: deliveries=%d err=%v", len(secondDeliveries), secondErr)
	}
	for _, delivery := range firstDeliveries {
		if err := delivery.Nak(context.Background(), 10*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	takeover, err := second.Fetch(context.Background())
	if err != nil || len(takeover) == 0 {
		t.Fatalf("second instance did not take over released lease: deliveries=%d err=%v", len(takeover), err)
	}
	for _, delivery := range takeover {
		if err := delivery.Ack(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	before, err := jetstream.StreamInfo(config.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := jetstream.DeleteStream(config.Stream); err != nil {
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(expectedIngestStream(config)); err != nil {
		t.Fatal(err)
	}
	if _, err := jetstream.AddConsumer(config.Stream, expectedConsumer(config)); err != nil {
		t.Fatal(err)
	}
	after, err := jetstream.StreamInfo(config.Stream)
	if err != nil || after.Created.Equal(before.Created) {
		t.Fatalf("stream epoch did not change: before=%s after=%s err=%v", before.Created, after.Created, err)
	}
	reopened, err := NewNATSIngestConsumer(connection, config)
	if err == nil {
		defer reopened.Close()
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "epoch") {
		t.Fatalf("stream recreation was not rejected by durable epoch state: %v", err)
	}
}

func TestOBSUsageAMaxDeliverParkedMessageIsRecoveredUnderLease(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	config.MaxDeliver = 2
	keyProvider := newRotatingIsolationKeyProvider()
	config.IsolationKeyProvider = keyProvider
	defer func() {
		_ = jetstream.DeleteConsumer(config.Stream, config.Durable)
		_ = jetstream.DeleteStream(config.Stream)
		_ = jetstream.DeleteStream(config.IsolationStream)
		for _, bucket := range obsUsageACoordinationBuckets(config) {
			_ = jetstream.DeleteKeyValue(bucket)
		}
	}()
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	sink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeIngestWriter{accessErrors: []error{
		ErrTransport, ErrTransport, ErrTransport, ErrTransport, ErrTransport, ErrTransport,
	}}
	processor := mustProcessor(t, time.Now().UTC(), writer, sink, IngestProcessorConfig{
		OperationTimeout: 5 * time.Second, MaxDeliver: config.MaxDeliver,
		NakBaseDelay: 10 * time.Millisecond, NakMaxDelay: 20 * time.Millisecond,
	})

	now := time.Now().UTC().Truncate(time.Millisecond)
	event := validAccessEvent("terminal-event")
	event.ConfigVersion = testConfigVersionID
	event.OccurredAt = now.Add(-time.Minute)
	publishAccessEnvelope(t, jetstream, config.Stream, "terminal-message", now, []AccessEvent{event})
	first, fetchErr := consumer.Fetch(context.Background())
	if fetchErr != nil || len(first) != 1 || first[0].Attempts() != 1 {
		t.Fatalf("first deliveries=%d metadata_attempt=%d err=%v", len(first), deliveryAttempts(first), fetchErr)
	}
	firstResult, firstErr := processor.Process(context.Background(), first)
	if firstErr != nil || firstResult.Naked != 1 || firstResult.Terminated != 0 {
		t.Fatalf("first result=%#v err=%v", firstResult, firstErr)
	}
	terminal, fetchErr := consumer.Fetch(context.Background())
	if fetchErr != nil || len(terminal) != 1 || terminal[0].Attempts() != 2 {
		t.Fatalf("cap deliveries=%d metadata_attempt=%d err=%v", len(terminal), deliveryAttempts(terminal), fetchErr)
	}
	terminalResult, terminalErr := processor.Process(context.Background(), terminal)
	if terminalErr != nil || terminalResult.Terminated != 1 || terminalResult.Naked != 0 {
		t.Fatalf("terminal result=%#v err=%v", terminalResult, terminalErr)
	}
	if info, err := jetstream.StreamInfo(config.IsolationStream); err != nil {
		t.Fatal(err)
	} else if info.State.Msgs != 1 {
		t.Fatalf("isolation evidence messages=%d", info.State.Msgs)
	}
	if replayed, err := consumer.Fetch(context.Background()); !errors.Is(err, ErrNoIngestMessages) || len(replayed) != 0 {
		t.Fatalf("terminal message replayed: deliveries=%d err=%v", len(replayed), err)
	}

	event.EventID = "crash-event"
	publishAccessEnvelope(t, jetstream, config.Stream, "crash-message", now, []AccessEvent{event})
	crashFirst, fetchErr := consumer.Fetch(context.Background())
	if fetchErr != nil || len(crashFirst) != 1 {
		t.Fatalf("crash first deliveries=%d err=%v", len(crashFirst), fetchErr)
	}
	if result, err := processor.Process(context.Background(), crashFirst); err != nil || result.Naked != 1 {
		t.Fatalf("crash first result=%#v err=%v", result, err)
	}
	crashCap, fetchErr := consumer.Fetch(context.Background())
	if fetchErr != nil || len(crashCap) != 1 || crashCap[0].Attempts() != 2 {
		t.Fatalf("crash cap deliveries=%d metadata_attempt=%d err=%v", len(crashCap), deliveryAttempts(crashCap), fetchErr)
	}
	record := isolationRecord(crashCap[0], "WRITER_RETRY_EXHAUSTED", time.Now().UTC())
	record.WireEvidenceOnly = true
	if err := sink.RecordTerminal(context.Background(), crashCap[0], record); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}

	takeover, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer takeover.Close()
	var recovered []IngestDelivery
	deadline := time.Now().Add(4 * config.AckWait)
	for len(recovered) == 0 && time.Now().Before(deadline) {
		recovered, err = takeover.Fetch(context.Background())
		if errors.Is(err, ErrNoIngestMessages) {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(recovered) != 1 || recovered[0].MessageID() != "crash-message" {
		t.Fatalf("terminal marker recovery deliveries=%d err=%v", len(recovered), err)
	}
	recoveryWriter := &fakeIngestWriter{accessErrors: []error{ErrTransport}}
	recoveryProcessor := mustProcessor(t, time.Now().UTC(), recoveryWriter, sink, IngestProcessorConfig{
		OperationTimeout: 5 * time.Second, MaxDeliver: config.MaxDeliver,
		NakBaseDelay: 10 * time.Millisecond, NakMaxDelay: 20 * time.Millisecond,
	})
	recoveredResult, recoveredErr := recoveryProcessor.Process(context.Background(), recovered)
	if recoveredErr != nil || recoveredResult.Terminated != 1 || recoveryWriter.accessCalls != 0 {
		t.Fatalf("recovered result=%#v writer_calls=%d err=%v", recoveredResult, recoveryWriter.accessCalls, recoveredErr)
	}
	if info, err := jetstream.StreamInfo(config.IsolationStream); err != nil {
		t.Fatal(err)
	} else if info.State.Msgs != 2 {
		t.Fatalf("deduplicated isolation evidence messages=%d", info.State.Msgs)
	}
	if replayed, err := takeover.Fetch(context.Background()); !errors.Is(err, ErrNoIngestMessages) || len(replayed) != 0 {
		t.Fatalf("recovered terminal message replayed: deliveries=%d err=%v", len(replayed), err)
	}

	keyProvider.retire("kek-v1")
	event.EventID = "key-unavailable-event"
	publishAccessEnvelope(t, jetstream, config.Stream, "key-unavailable-message", now, []AccessEvent{event})
	keyFirst, fetchErr := takeover.Fetch(context.Background())
	if fetchErr != nil || len(keyFirst) != 1 {
		t.Fatalf("key unavailable first deliveries=%d err=%v", len(keyFirst), fetchErr)
	}
	if result, err := processor.Process(context.Background(), keyFirst); err != nil || result.Naked != 1 {
		t.Fatalf("key unavailable first result=%#v err=%v", result, err)
	}
	keyCap, fetchErr := takeover.Fetch(context.Background())
	if fetchErr != nil || len(keyCap) != 1 || keyCap[0].Attempts() != 2 {
		t.Fatalf("key unavailable cap deliveries=%d metadata_attempt=%d err=%v",
			len(keyCap), deliveryAttempts(keyCap), fetchErr)
	}
	keyResult, keyErr := processor.Process(context.Background(), keyCap)
	if keyErr == nil || keyResult.Naked != 1 || keyResult.Terminated != 0 {
		t.Fatalf("key unavailable cap result=%#v err=%v", keyResult, keyErr)
	}
	if info, err := jetstream.StreamInfo(config.IsolationStream); err != nil {
		t.Fatal(err)
	} else if info.State.Msgs != 2 {
		t.Fatalf("key failure persisted unexpected isolation evidence messages=%d", info.State.Msgs)
	}
}

func obsUsageAJetStreamConfig() JetStreamConfig {
	config := DefaultJetStreamConfig()
	suffix := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano())
	config.Stream = "ANALYTICS_HA_" + suffix
	config.Durable = "analytics_ha_" + suffix
	config.IsolationStream = "ANALYTICS_ISOLATION_HA_" + suffix
	config.AckWait = 7 * time.Second
	config.FetchTimeout = 500 * time.Millisecond
	config.OperationTimeout = 2 * time.Second
	config.NakBaseDelay = 10 * time.Millisecond
	config.NakMaxDelay = 20 * time.Millisecond
	config.FetchBatch = 1
	config.MaxAckPending = 2
	config.MaxWaiting = 2
	config.StreamMaxBytes = 16 << 20
	config.StreamMaxMessages = 100
	config.IsolationMaxBytes = 4 << 20
	config.IsolationMaxAge = time.Hour
	config.DuplicateWindow = time.Minute
	return config
}

func obsUsageACoordinationBuckets(config JetStreamConfig) []string {
	digest := sha256Sum([]byte(config.Stream + "\x00" + config.Durable))
	suffix := fmt.Sprintf("%x", digest[:8])
	return []string{"AISTATE_" + suffix, "AILEASE_" + suffix, isolationEvidenceBucketName(config)}
}

// ensureProvisionedOBSUsageAJetStream preprovisions the AIEVIDENCE KV the way
// the installer does (runtime never creates it, see round14) and then runs the
// production EnsureIngestJetStream contract.
func ensureProvisionedOBSUsageAJetStream(connection *nats.Conn, config JetStreamConfig) error {
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return err
	}
	if _, err := jetstream.KeyValue(isolationEvidenceBucketName(config)); errors.Is(err, nats.ErrBucketNotFound) {
		if _, err := jetstream.CreateKeyValue(&nats.KeyValueConfig{
			Bucket: isolationEvidenceBucketName(config), History: 1, TTL: 0,
			MaxValueSize: isolationEvidenceMaxValueSize, MaxBytes: config.IsolationMaxBytes,
			Storage: nats.FileStorage, Replicas: config.Replicas,
		}); err != nil {
			return err
		}
	}
	return EnsureIngestJetStream(context.Background(), connection, config)
}

func deliveryAttempts(deliveries []IngestDelivery) uint64 {
	if len(deliveries) == 0 {
		return 0
	}
	return deliveries[0].Attempts()
}
