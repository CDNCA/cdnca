//go:build integration

package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestOBSUsageAFinalFetchPersistsReplayStateBeforeSettlement(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.MaxDeliver = 2
	config.OperationTimeout = 100 * time.Millisecond
	config.FetchTimeout = 50 * time.Millisecond
	config.AckWait = 500 * time.Millisecond
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	event := validAccessEvent("final-fetch-crash-event")
	event.ConfigVersion = testConfigVersionID
	event.OccurredAt = now.Add(-time.Minute)
	publishAccessEnvelope(t, jetstream, config.Stream, "final-fetch-crash-message", now, []AccessEvent{event})

	first, err := consumer.Fetch(context.Background())
	if err != nil || len(first) != 1 || first[0].Attempts() != 1 {
		t.Fatalf("first fetch deliveries=%d attempts=%d err=%v", len(first), deliveryAttempts(first), err)
	}
	if err := first[0].Nak(context.Background(), 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	final, err := consumer.Fetch(context.Background())
	if err != nil || len(final) != 1 || final[0].Attempts() != 2 {
		t.Fatalf("final fetch deliveries=%d attempts=%d err=%v", len(final), deliveryAttempts(final), err)
	}
	state, err := consumer.stateStore.Get(parkedStateKey(final[0].StreamSequence()))
	if err != nil || len(state.Value()) == 0 {
		t.Fatalf("final delivery became terminal without durable replay state: entry=%v err=%v", state, err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	deadline := time.Now().Add(config.AckWait + 2*config.FetchTimeout)
	var replayed []IngestDelivery
	for {
		replayed, err = restarted.Fetch(context.Background())
		if !errors.Is(err, ErrNoIngestMessages) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || len(replayed) != 1 || replayed[0].MessageID() != "final-fetch-crash-message" {
		t.Fatalf("final-fetch crash was not recovered after restart: deliveries=%d err=%v", len(replayed), err)
	}
	if err := replayed[0].Ack(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOBSUsageASettlementRejectsNaturallyExpiredOwner(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	oldOwner, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer oldOwner.Close()
	newOwner, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer newOwner.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	event := validAccessEvent("lease-expiry-event")
	event.ConfigVersion = testConfigVersionID
	event.OccurredAt = now.Add(-time.Minute)
	publishAccessEnvelope(t, jetstream, config.Stream, "lease-expiry-message", now, []AccessEvent{event})
	deliveries, err := oldOwner.Fetch(context.Background())
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("old owner fetch deliveries=%d err=%v", len(deliveries), err)
	}

	oldOwner.leaseMu.Lock()
	if oldOwner.leaseStop == nil {
		oldOwner.leaseMu.Unlock()
		t.Fatal("old owner did not start a lease heartbeat")
	}
	close(oldOwner.leaseStop)
	oldOwner.leaseStop = nil
	oldOwner.leaseMu.Unlock()

	deadline := time.Now().Add(4 * coordinationLeaseTTL(config))
	for {
		acquired, acquireErr := newOwner.acquireOrRenewLease()
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		if acquired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new owner did not acquire the naturally expired lease")
		}
		time.Sleep(25 * time.Millisecond)
	}

	if err := deliveries[0].Ack(context.Background()); err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("stale owner settled after natural TTL takeover: %v", err)
	}
}

func TestOBSUsageAIsolationWireIsEncryptedReplayableAndTamperEvident(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
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

	const secret = "poison-wire-secret-must-not-be-plaintext"
	poison := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
	poison.Data = []byte(`{"schema_version":1,"type":"poison.v1","message_id":"encrypted-poison-message","secret":"` + secret + `"}`)
	poison.Header.Set(nats.MsgIdHdr, "encrypted-poison-message")
	poison.Header.Set(ingestNodeHeader, testNodeID)
	poison.Header.Set(ingestTenantHeader, testTenantID)
	poison.Header.Set(ingestSiteHeader, testSiteID)
	poison.Header.Set(ingestConfigHeader, testConfigVersionID)
	poison.Header.Set(ingestInstallHeader, "installation-reviewer")
	ack, err := jetstream.PublishMsg(poison)
	if err != nil || ack == nil || ack.Stream != config.Stream {
		t.Fatalf("publish poison ack=%+v err=%v", ack, err)
	}
	deliveries, err := consumer.Fetch(context.Background())
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poison fetch deliveries=%d err=%v", len(deliveries), err)
	}
	record := isolationRecord(deliveries[0], RejectInvalidJSON, time.Now().UTC())
	wrongWire := record
	wrongWire.Wire = &IsolationWire{
		Subject: record.Wire.Subject, Payload: append([]byte(nil), record.Wire.Payload...),
		Headers: append([]IsolationHeader(nil), record.Wire.Headers...),
	}
	wrongWire.Wire.Headers[1].Value = "40000000-0000-0000-0000-000000000001"
	if err := sink.Record(context.Background(), wrongWire); err == nil {
		t.Fatal("wrong-identity isolation wire was persisted")
	}
	if err := sink.Record(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != 1 || info.Config.MaxAge != config.IsolationMaxAge {
		t.Fatalf("isolation idempotency/retention state=%+v err=%v", info, err)
	}
	stored, err := jetstream.GetMsg(config.IsolationStream, info.State.FirstSeq)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored.Data, []byte(secret)) || bytes.Contains(stored.Data, poison.Data) {
		t.Fatal("isolation persistence leaked plaintext/raw poison wire")
	}
	var encoded map[string]any
	if err := json.Unmarshal(stored.Data, &encoded); err != nil {
		t.Fatal(err)
	}
	if encoded["wire_ciphertext"] == nil || encoded["wire_nonce"] == nil || encoded["wire_sha256"] == nil {
		t.Fatalf("isolation record has no encrypted replay fact: %s", stored.Data)
	}

	replay := reflect.ValueOf(sink).MethodByName("Replay")
	if !replay.IsValid() {
		t.Fatal("isolation sink has no replay verifier")
	}
	callReplay := func(payload []byte) (*nats.Msg, error) {
		values := replay.Call([]reflect.Value{reflect.ValueOf(payload)})
		message, _ := values[0].Interface().(*nats.Msg)
		var replayErr error
		if !values[1].IsNil() {
			replayErr, _ = values[1].Interface().(error)
		}
		return message, replayErr
	}
	replayed, err := callReplay(stored.Data)
	if err != nil || replayed == nil || replayed.Subject != poison.Subject || !bytes.Equal(replayed.Data, poison.Data) ||
		!reflect.DeepEqual(replayed.Header, poison.Header) {
		t.Fatalf("exact isolation replay failed: message=%+v err=%v", replayed, err)
	}
	replayedAgain, err := callReplay(stored.Data)
	if err != nil || replayedAgain == nil || !bytes.Equal(replayedAgain.Data, poison.Data) {
		t.Fatalf("idempotent isolation replay failed: message=%+v err=%v", replayedAgain, err)
	}

	tampered := append([]byte(nil), stored.Data...)
	for index := range tampered {
		if tampered[index] >= 'A' && tampered[index] <= 'Z' {
			tampered[index] ^= 1
			break
		}
	}
	if _, err := callReplay(tampered); err == nil {
		t.Fatal("tampered isolation wire replay did not fail closed")
	}
}

func cleanupOBSUsageAJetStream(t *testing.T, jetstream nats.JetStreamContext, config JetStreamConfig) {
	t.Helper()
	_ = jetstream.DeleteConsumer(config.Stream, config.Durable)
	_ = jetstream.DeleteStream(config.Stream)
	_ = jetstream.DeleteStream(config.IsolationStream)
	for _, bucket := range obsUsageACoordinationBuckets(config) {
		_ = jetstream.DeleteKeyValue(bucket)
	}
}

func parkedStateKey(sequence uint64) string {
	return fmt.Sprintf("parked.%020d", sequence)
}
