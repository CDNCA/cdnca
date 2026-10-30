//go:build integration

package analytics

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type pausedLeaseKeyValue struct {
	nats.KeyValue
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (value *pausedLeaseKeyValue) pause() {
	value.once.Do(func() {
		close(value.entered)
		<-value.release
	})
}

func (value *pausedLeaseKeyValue) Get(key string) (nats.KeyValueEntry, error) {
	entry, err := value.KeyValue.Get(key)
	if key == "active" && err == nil {
		value.pause()
	}
	return entry, err
}

func (value *pausedLeaseKeyValue) Update(key string, payload []byte, revision uint64) (uint64, error) {
	if key == "active" {
		value.pause()
	}
	return value.KeyValue.Update(key, payload, revision)
}

func stopOBSUsageALeaseHeartbeat(t *testing.T, consumer *NATSIngestConsumer) {
	t.Helper()
	consumer.leaseMu.Lock()
	defer consumer.leaseMu.Unlock()
	if consumer.leaseStop == nil {
		t.Fatal("consumer did not start a lease heartbeat")
	}
	close(consumer.leaseStop)
	consumer.leaseStop = nil
}

func staleOBSUsageAOwnerAction(
	t *testing.T,
	oldOwner, newOwner *NATSIngestConsumer,
	action func() error,
) error {
	t.Helper()
	stopOBSUsageALeaseHeartbeat(t, oldOwner)
	paused := &pausedLeaseKeyValue{
		KeyValue: oldOwner.leaseStore, entered: make(chan struct{}), release: make(chan struct{}),
	}
	oldOwner.leaseStore = paused
	done := make(chan error, 1)
	go func() { done <- action() }()
	select {
	case <-paused.entered:
	case <-time.After(2 * coordinationLeaseTTL(oldOwner.config)):
		t.Fatal("stale action never reached its remote lease fence")
	}
	deadline := time.Now().Add(4 * coordinationLeaseTTL(oldOwner.config))
	for {
		acquired, err := newOwner.acquireOrRenewLease()
		if err != nil {
			t.Fatal(err)
		}
		if acquired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new owner did not acquire the naturally expired lease")
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(paused.release)
	select {
	case err := <-done:
		return err
	case <-time.After(2 * oldOwner.config.OperationTimeout):
		t.Fatal("stale owner action did not return after takeover")
		return nil
	}
}

func staleOBSUsageAOwnerActionAfterRenewal(
	t *testing.T,
	oldOwner, newOwner *NATSIngestConsumer,
	action func(context.Context) error,
) error {
	t.Helper()
	stopOBSUsageALeaseHeartbeat(t, oldOwner)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- oldOwner.withLeaseFence(func(ctx context.Context) error {
			close(entered)
			<-release
			return action(ctx)
		})
	}()
	select {
	case <-entered:
	case <-time.After(2 * coordinationLeaseTTL(oldOwner.config)):
		t.Fatal("stale action never entered its closure after successful lease renewal")
	}
	deadline := time.Now().Add(4 * coordinationLeaseTTL(oldOwner.config))
	for {
		acquired, err := newOwner.acquireOrRenewLease()
		if err != nil {
			t.Fatal(err)
		}
		if acquired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new owner did not acquire the naturally expired renewed lease")
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(release)
	select {
	case err := <-done:
		return err
	case <-time.After(2 * oldOwner.config.OperationTimeout):
		t.Fatal("stale owner action did not return after post-renewal takeover")
		return nil
	}
}

func TestOBSUsageAStaleOwnerCannotMutateAfterSuccessfulRenewalPause(t *testing.T) {
	for _, mutation := range []string{"delete", "epoch", "parked-cleanup", "ack", "nak", "term"} {
		t.Run(mutation, func(t *testing.T) {
			_, jetstream, config, oldOwner, newOwner := newOBSUsageALeaseOwners(t)
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			defer oldOwner.Close()
			defer newOwner.Close()
			if acquired, err := oldOwner.acquireOrRenewLease(); err != nil || !acquired {
				t.Fatalf("old owner lease acquired=%v err=%v", acquired, err)
			}

			var action func(context.Context) error
			switch mutation {
			case "delete":
				action = func(ctx context.Context) error {
					return jetstream.DeleteConsumer(config.Stream, config.Durable, nats.Context(ctx))
				}
			case "epoch":
				action = func(ctx context.Context) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					return setEpoch(oldOwner.stateStore, "consumer_created", oldOwner.consumerCreated.Add(time.Second))
				}
			case "parked-cleanup":
				if _, err := oldOwner.stateStore.Create(parkedStateKey(1), []byte(`{"owner":"new"}`)); err != nil {
					t.Fatal(err)
				}
				action = func(ctx context.Context) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					return oldOwner.stateStore.Delete(parkedStateKey(1))
				}
			default:
				now := time.Now().UTC().Truncate(time.Millisecond)
				event := validAccessEvent("post-renewal-" + mutation)
				event.ConfigVersion = testConfigVersionID
				event.OccurredAt = now.Add(-time.Minute)
				publishAccessEnvelope(t, jetstream, config.Stream, "post-renewal-"+mutation, now, []AccessEvent{event})
				deliveries, err := oldOwner.Fetch(context.Background())
				if err != nil || len(deliveries) != 1 {
					t.Fatalf("fetch settlement delivery=%d err=%v", len(deliveries), err)
				}
				delivery := deliveries[0].(*natsIngestDelivery)
				action = func(ctx context.Context) error {
					switch mutation {
					case "ack":
						return delivery.message.AckSync(nats.Context(ctx))
					case "nak":
						return delivery.message.NakWithDelay(10*time.Millisecond, nats.Context(ctx))
					default:
						return delivery.message.Term(nats.Context(ctx))
					}
				}
			}
			if err := staleOBSUsageAOwnerActionAfterRenewal(t, oldOwner, newOwner, action); err == nil {
				t.Fatalf("stale owner completed %s after renewed lease takeover", mutation)
			}
			if mutation == "delete" {
				if _, err := jetstream.ConsumerInfo(config.Stream, config.Durable); err != nil {
					t.Fatalf("stale delete removed durable: %v", err)
				}
			}
		})
	}
}

func newOBSUsageALeaseOwners(
	t *testing.T,
) (*nats.Conn, nats.JetStreamContext, JetStreamConfig, *NATSIngestConsumer, *NATSIngestConsumer) {
	t.Helper()
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	config.OperationTimeout = time.Second
	config.FetchTimeout = 250 * time.Millisecond
	config.AckWait = 8 * time.Second
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	oldOwner, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	newOwner, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	return connection, jetstream, config, oldOwner, newOwner
}

func TestOBSUsageAStaleOwnerCannotExecuteRecoveryMutationAfterFencePause(t *testing.T) {
	t.Run("delete durable", func(t *testing.T) {
		_, jetstream, config, oldOwner, newOwner := newOBSUsageALeaseOwners(t)
		defer cleanupOBSUsageAJetStream(t, jetstream, config)
		defer oldOwner.Close()
		defer newOwner.Close()
		if acquired, err := oldOwner.acquireOrRenewLease(); err != nil || !acquired {
			t.Fatalf("old owner lease acquired=%v err=%v", acquired, err)
		}
		err := staleOBSUsageAOwnerAction(t, oldOwner, newOwner, func() error {
			return oldOwner.withLeaseFence(func(ctx context.Context) error {
				return jetstream.DeleteConsumer(config.Stream, config.Durable, nats.Context(ctx))
			})
		})
		if err == nil || !strings.Contains(err.Error(), "lease") {
			t.Fatalf("stale owner deleted durable after takeover: %v", err)
		}
		if _, err := jetstream.ConsumerInfo(config.Stream, config.Durable); err != nil {
			t.Fatalf("stale owner changed durable consumer: %v", err)
		}
	})

	t.Run("update epoch", func(t *testing.T) {
		_, jetstream, config, oldOwner, newOwner := newOBSUsageALeaseOwners(t)
		defer cleanupOBSUsageAJetStream(t, jetstream, config)
		defer oldOwner.Close()
		defer newOwner.Close()
		if acquired, err := oldOwner.acquireOrRenewLease(); err != nil || !acquired {
			t.Fatalf("old owner lease acquired=%v err=%v", acquired, err)
		}
		before, err := oldOwner.stateStore.Get("consumer_created")
		if err != nil {
			t.Fatal(err)
		}
		target := oldOwner.consumerCreated.Add(time.Second)
		err = staleOBSUsageAOwnerAction(t, oldOwner, newOwner, func() error {
			return oldOwner.withLeaseFence(func(ctx context.Context) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				return setEpoch(oldOwner.stateStore, "consumer_created", target)
			})
		})
		if err == nil || !strings.Contains(err.Error(), "lease") {
			t.Fatalf("stale owner updated epoch after takeover: %v", err)
		}
		after, err := oldOwner.stateStore.Get("consumer_created")
		if err != nil || !bytes.Equal(after.Value(), before.Value()) {
			t.Fatalf("stale owner changed epoch: before=%q after=%q err=%v", before.Value(), after.Value(), err)
		}
	})
}

func TestOBSUsageAStaleOwnerCannotMarkTerminalParkedAfterTakeover(t *testing.T) {
	_, jetstream, config, oldOwner, newOwner := newOBSUsageALeaseOwners(t)
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	defer oldOwner.Close()
	defer newOwner.Close()
	if acquired, err := oldOwner.acquireOrRenewLease(); err != nil || !acquired {
		t.Fatalf("old owner lease acquired=%v err=%v", acquired, err)
	}
	before, err := jetstream.ConsumerInfo(config.Stream, config.Durable)
	if err != nil {
		t.Fatal(err)
	}
	err = staleOBSUsageAOwnerAction(t, oldOwner, newOwner, func() error {
		return oldOwner.markParked(1)
	})
	if err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("stale owner persisted terminal parked state after takeover: %v", err)
	}
	if _, err := oldOwner.stateStore.Get(parkedStateKey(1)); !errors.Is(err, nats.ErrKeyNotFound) {
		t.Fatalf("stale owner left terminal parked state after takeover: %v", err)
	}
	if deliveries, err := newOwner.Fetch(context.Background()); !errors.Is(err, ErrNoIngestMessages) || len(deliveries) != 0 {
		t.Fatalf("stale marker triggered recovery: deliveries=%d err=%v", len(deliveries), err)
	}
	after, err := jetstream.ConsumerInfo(config.Stream, config.Durable)
	if err != nil || !after.Created.Equal(before.Created) {
		t.Fatalf("stale marker reset the new owner's durable: before=%s after=%s err=%v", before.Created, after.Created, err)
	}
}

func TestOBSUsageAStaleOwnerCannotConfirmTerminalEvidenceAfterTakeover(t *testing.T) {
	_, jetstream, config, oldOwner, newOwner := newOBSUsageALeaseOwners(t)
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	defer oldOwner.Close()
	defer newOwner.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	event := validAccessEvent("stale-terminal-evidence")
	event.ConfigVersion = testConfigVersionID
	event.OccurredAt = now.Add(-time.Minute)
	publishAccessEnvelope(t, jetstream, config.Stream, "stale-terminal-evidence", now, []AccessEvent{event})
	deliveries, err := oldOwner.Fetch(context.Background())
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("old owner fetch deliveries=%d err=%v", len(deliveries), err)
	}
	delivery := deliveries[0].(*natsIngestDelivery)
	record := isolationRecord(delivery, writerExhaustedReason, now)
	record.WireEvidenceOnly = true
	err = staleOBSUsageAOwnerAction(t, oldOwner, newOwner, func() error {
		return delivery.ConfirmTerminalEvidence(context.Background(), record)
	})
	if err == nil || !strings.Contains(err.Error(), "lease") {
		t.Fatalf("stale owner confirmed terminal evidence after takeover: %v", err)
	}
	entry, err := oldOwner.stateStore.Get(parkedStateKey(delivery.streamSequence))
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
	if err != nil || state.EvidenceConfirmed {
		t.Fatalf("stale owner mutated terminal evidence state: state=%#v err=%v", state, err)
	}
}

func TestOBSUsageAStaleOwnerCannotSettleAfterFencePause(t *testing.T) {
	for _, settlement := range []string{"ack", "nak", "term"} {
		t.Run(settlement, func(t *testing.T) {
			_, jetstream, config, oldOwner, newOwner := newOBSUsageALeaseOwners(t)
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			defer oldOwner.Close()
			defer newOwner.Close()

			now := time.Now().UTC().Truncate(time.Millisecond)
			event := validAccessEvent("stale-settlement-" + settlement)
			event.ConfigVersion = testConfigVersionID
			event.OccurredAt = now.Add(-time.Minute)
			messageID := "stale-settlement-message-" + settlement
			publishAccessEnvelope(t, jetstream, config.Stream, messageID, now, []AccessEvent{event})
			deliveries, err := oldOwner.Fetch(context.Background())
			if err != nil || len(deliveries) != 1 {
				t.Fatalf("old owner fetch deliveries=%d err=%v", len(deliveries), err)
			}
			delivery := deliveries[0]
			err = staleOBSUsageAOwnerAction(t, oldOwner, newOwner, func() error {
				switch settlement {
				case "ack":
					return delivery.Ack(context.Background())
				case "nak":
					return delivery.Nak(context.Background(), 10*time.Millisecond)
				default:
					return delivery.Term(context.Background())
				}
			})
			if err == nil || !strings.Contains(err.Error(), "lease") {
				t.Fatalf("stale owner executed %s after takeover: %v", settlement, err)
			}
			if settlement == "nak" {
				immediate, fetchErr := newOwner.Fetch(context.Background())
				if !errors.Is(fetchErr, ErrNoIngestMessages) || len(immediate) != 0 {
					t.Fatalf("stale NAK changed delivery timing: deliveries=%d err=%v", len(immediate), fetchErr)
				}
			}
			time.Sleep(config.AckWait + 100*time.Millisecond)
			replayed, fetchErr := newOwner.Fetch(context.Background())
			if fetchErr != nil || len(replayed) != 1 || replayed[0].MessageID() != messageID {
				t.Fatalf("stale %s made message terminal: deliveries=%d err=%v", settlement, len(replayed), fetchErr)
			}
			if err := replayed[0].Ack(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func setIsolationKeyProvider(t *testing.T, config *JetStreamConfig, provider any) {
	t.Helper()
	field := reflect.ValueOf(config).Elem().FieldByName("IsolationKeyProvider")
	if !field.IsValid() || !field.CanSet() {
		t.Fatal("JetStreamConfig has no caller-injected IsolationKeyProvider")
	}
	value := reflect.ValueOf(provider)
	if !value.Type().AssignableTo(field.Type()) {
		t.Fatalf("provider %s does not implement %s", value.Type(), field.Type())
	}
	field.Set(value)
}

func TestOBSUsageAIsolationSameStoreDisclosureRotationAndRetirement(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	config.OperationTimeout = time.Second
	config.AckWait = 5 * time.Second
	provider := newRotatingIsolationKeyProvider()
	setIsolationKeyProvider(t, &config, provider)
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	sink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}

	first := reviewerIsolationRecord("rotation-one", "secret-one")
	if err := sink.Record(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	provider.rotate("kek-v2")
	secondSink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	second := reviewerIsolationRecord("rotation-two", "secret-two")
	if err := secondSink.Record(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != 2 {
		t.Fatalf("isolation rotation stream state=%+v err=%v", info, err)
	}
	firstStored, err := jetstream.GetMsg(config.IsolationStream, info.State.FirstSeq)
	if err != nil {
		t.Fatal(err)
	}
	secondStored, err := jetstream.GetMsg(config.IsolationStream, info.State.LastSeq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondSink.Replay(firstStored.Data); err != nil {
		t.Fatalf("non-retired key rotation lost old replay: %v", err)
	}
	if _, err := secondSink.Replay(secondStored.Data); err != nil {
		t.Fatalf("active key replay failed: %v", err)
	}
	provider.retire("kek-v1")
	if _, err := secondSink.Replay(firstStored.Data); err == nil {
		t.Fatal("retired isolation KEK still decrypted old wire")
	}
	if _, err := secondSink.Replay(secondStored.Data); err != nil {
		t.Fatalf("retiring v1 broke v2 replay: %v", err)
	}

	stateStore, _, err := ensureCoordinationStores(jetstream, config)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := stateStore.Keys()
	if err != nil {
		t.Fatal(err)
	}
	foundWrappedV2 := false
	for _, key := range keys {
		entry, getErr := stateStore.Get(key)
		if getErr != nil {
			t.Fatal(getErr)
		}
		for _, plaintextKEK := range provider.keys {
			if bytes.Contains(entry.Value(), plaintextKEK) {
				t.Fatalf("NATS state key %q disclosed plaintext KEK", key)
			}
		}
		if bytes.Contains(entry.Value(), []byte(`"key_id":"kek-v2"`)) {
			foundWrappedV2 = true
			tampered := append([]byte(nil), entry.Value()...)
			tampered[len(tampered)-2] ^= 1
			if _, err := stateStore.Update(key, tampered, entry.Revision()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !foundWrappedV2 {
		t.Fatal("state store has no versioned wrapped v2 DEK")
	}
	if _, err := secondSink.Replay(secondStored.Data); err == nil {
		t.Fatal("tampered wrapped DEK did not fail closed")
	}
	if strings.Contains(string(secondStored.Data), "secret-two") {
		t.Fatal("isolation stream leaked plaintext wire")
	}
}

func reviewerIsolationRecord(messageID, secret string) IsolationRecord {
	payload := []byte(`{"schema_version":1,"type":"poison.v1","message_id":"` + messageID + `","secret":"` + secret + `"}`)
	digest := sha256Sum(payload)
	return IsolationRecord{
		SchemaVersion:  IngestSchemaVersion,
		ReasonCode:     RejectInvalidJSON,
		MessageID:      messageID,
		Subject:        IngestSubjectPrefix + "." + testNodeID,
		PayloadSHA256:  fmt.Sprintf("%x", digest[:]),
		PayloadBytes:   len(payload),
		Attempts:       2,
		StreamSequence: uint64(len(messageID)),
		IsolatedAt:     time.Now().UTC().Truncate(time.Millisecond),
		Wire: &IsolationWire{
			Subject: IngestSubjectPrefix + "." + testNodeID,
			Headers: []IsolationHeader{
				{Name: nats.MsgIdHdr, Value: messageID},
				{Name: ingestNodeHeader, Value: testNodeID},
				{Name: ingestTenantHeader, Value: testTenantID},
				{Name: ingestSiteHeader, Value: testSiteID},
				{Name: ingestConfigHeader, Value: testConfigVersionID},
				{Name: ingestInstallHeader, Value: "installation-reviewer"},
			},
			Payload: payload,
		},
	}
}

type delayedKeyValue struct {
	nats.KeyValue
	delay     time.Duration
	delayOnce *sync.Once
}

func (value delayedKeyValue) wait() {
	value.delayOnce.Do(func() {
		time.Sleep(value.delay)
	})
}

func (value delayedKeyValue) Keys(options ...nats.WatchOpt) ([]string, error) {
	value.wait()
	return value.KeyValue.Keys(options...)
}

func (value delayedKeyValue) Get(key string) (nats.KeyValueEntry, error) {
	value.wait()
	return value.KeyValue.Get(key)
}

func (value delayedKeyValue) Delete(key string, options ...nats.DeleteOpt) error {
	value.wait()
	return value.KeyValue.Delete(key, options...)
}

func TestOBSUsageARecoveryDoesNotLetLeaseExpireDuringSlowStateIO(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	config.OperationTimeout = 500 * time.Millisecond
	config.AckWait = 2 * time.Second
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

	streamInfo, err := jetstream.StreamInfo(config.Stream)
	if err != nil {
		t.Fatal(err)
	}
	parked := parkedDeliveryState{
		StreamCreated: streamInfo.Created.UTC().Format(time.RFC3339Nano),
		OwnerID:       "crashed-owner", Terminal: true,
	}
	encoded, _ := json.Marshal(parked)
	if _, err := oldOwner.stateStore.Create(parkedStateKey(1), encoded); err != nil {
		t.Fatal(err)
	}
	oldOwner.stateStore = delayedKeyValue{
		KeyValue:  oldOwner.stateStore,
		delay:     coordinationLeaseTTL(config),
		delayOnce: new(sync.Once),
	}
	done := make(chan error, 1)
	go func() {
		_, fetchErr := oldOwner.Fetch(context.Background())
		done <- fetchErr
	}()
	deadline := time.Now().Add(2 * coordinationLeaseTTL(config))
	for {
		if _, err := oldOwner.leaseStore.Get("active"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old owner never acquired lease")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(coordinationLeaseTTL(config) + 50*time.Millisecond)
	acquired, acquireErr := newOwner.acquireOrRenewLease()
	if acquireErr != nil {
		t.Fatal(acquireErr)
	}
	if acquired {
		t.Fatal("slow recovery blocked heartbeat until another owner acquired the live lease")
	}
	select {
	case <-done:
	case <-time.After(5 * coordinationLeaseTTL(config)):
		t.Fatal("slow recovery did not finish")
	}
}

type recoveryFixture struct {
	SchemaVersion         uint16 `json:"schema_version"`
	Phase                 string `json:"phase"`
	OwnerID               string `json:"owner_id"`
	StreamCreated         string `json:"stream_created"`
	SourceConsumerCreated string `json:"source_consumer_created"`
	TargetConsumerCreated string `json:"target_consumer_created,omitempty"`
}

func TestOBSUsageANewOwnerResumesEveryConsumerRecoveryBoundary(t *testing.T) {
	for _, phase := range []string{
		"prepared", "delete_pending", "deleted", "recreate_pending",
		"recreated", "epoch_pending", "epoch_updated", "cleanup_pending",
	} {
		t.Run(phase, func(t *testing.T) {
			connection, jetstream := connectJetStreamBlockerProof(t)
			config := obsUsageAJetStreamConfig()
			config.OperationTimeout = 2 * time.Second
			config.AckWait = 7 * time.Second
			config.FetchTimeout = time.Second
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
				t.Fatal(err)
			}
			baseline, err := NewNATSIngestConsumer(connection, config)
			if err != nil {
				t.Fatal(err)
			}
			if err := baseline.Close(); err != nil {
				t.Fatal(err)
			}
			streamInfo, err := jetstream.StreamInfo(config.Stream)
			if err != nil {
				t.Fatal(err)
			}
			consumerInfo, err := jetstream.ConsumerInfo(config.Stream, config.Durable)
			if err != nil {
				t.Fatal(err)
			}
			stateStore, _, err := ensureCoordinationStores(jetstream, config)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			event := validAccessEvent("recovery-boundary-" + phase)
			event.ConfigVersion = testConfigVersionID
			event.OccurredAt = now.Add(-time.Minute)
			messageID := "recovery-boundary-message-" + phase
			publishAccessEnvelope(t, jetstream, config.Stream, messageID, now, []AccessEvent{event})
			parked := parkedDeliveryState{
				StreamCreated: streamInfo.Created.UTC().Format(time.RFC3339Nano),
				OwnerID:       "crashed-owner", Terminal: true,
			}
			parkedJSON, _ := json.Marshal(parked)
			if _, err := stateStore.Create(parkedStateKey(1), parkedJSON); err != nil {
				t.Fatal(err)
			}

			targetCreated := ""
			consumerMissing := phase == "deleted" || phase == "recreate_pending"
			consumerRecreated := phase == "recreated" || phase == "epoch_pending" ||
				phase == "epoch_updated" || phase == "cleanup_pending"
			if consumerMissing || consumerRecreated {
				if err := jetstream.DeleteConsumer(config.Stream, config.Durable); err != nil {
					t.Fatal(err)
				}
			}
			if consumerRecreated {
				created, err := jetstream.AddConsumer(config.Stream, expectedConsumer(config))
				if err != nil {
					t.Fatal(err)
				}
				targetCreated = created.Created.UTC().Format(time.RFC3339Nano)
				if phase == "epoch_updated" || phase == "cleanup_pending" {
					entry, err := stateStore.Get("consumer_created")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := stateStore.Update("consumer_created", []byte(targetCreated), entry.Revision()); err != nil {
						t.Fatal(err)
					}
				}
			}
			fixture := recoveryFixture{
				SchemaVersion: 1, Phase: phase, OwnerID: "crashed-owner",
				StreamCreated:         streamInfo.Created.UTC().Format(time.RFC3339Nano),
				SourceConsumerCreated: consumerInfo.Created.UTC().Format(time.RFC3339Nano),
				TargetConsumerCreated: targetCreated,
			}
			fixtureJSON, _ := json.Marshal(fixture)
			if _, err := stateStore.Create("consumer_recovery.v1", fixtureJSON); err != nil {
				t.Fatal(err)
			}

			owner, err := NewNATSIngestConsumer(connection, config)
			if err != nil {
				t.Fatalf("new owner could not open phase %s: %v", phase, err)
			}
			defer owner.Close()
			deliveries, err := owner.Fetch(context.Background())
			if err != nil || len(deliveries) == 0 || deliveries[0].MessageID() != messageID {
				t.Fatalf("phase %s did not resume parked wire: deliveries=%d err=%v", phase, len(deliveries), err)
			}
			if err := deliveries[0].Ack(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := stateStore.Get("consumer_recovery.v1"); !errors.Is(err, nats.ErrKeyNotFound) {
				t.Fatalf("phase %s left recovery marker: %v", phase, err)
			}
		})
	}
}

func decryptOBSUsageAIsolationEvidence(
	t *testing.T,
	sink *NATSIsolationSink,
	payload []byte,
) (IsolationRecord, IsolationWire) {
	t.Helper()
	var record IsolationRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(record.WireNonce)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(record.WireCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := sink.loadIsolationDEK(context.Background(), record.WireKeyID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	wirePayload, err := aead.Open(nil, nonce, ciphertext, isolationAssociatedData(record))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wirePayload)
	var wire IsolationWire
	if err := json.Unmarshal(wirePayload, &wire); err != nil {
		t.Fatal(err)
	}
	return record, wire
}

func TestOBSUsageAMalformedAuthorityTerminatesWithEncryptedEvidence(t *testing.T) {
	tests := map[string]func(*nats.Msg){
		"missing": func(message *nats.Msg) {
			message.Header.Del(ingestInstallHeader)
		},
		"malformed": func(message *nats.Msg) {
			message.Header.Set(ingestTenantHeader, " malformed-tenant")
		},
		"extra": func(message *nats.Msg) {
			message.Header.Set("X-Authority-Secret", "must-remain-encrypted")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
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

			now := time.Now().UTC().Truncate(time.Millisecond)
			event := validAccessEvent("malformed-authority-" + name)
			event.ConfigVersion = testConfigVersionID
			event.OccurredAt = now.Add(-time.Minute)
			messageID := "malformed-authority-message-" + name
			message := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
			message.Header.Set(nats.MsgIdHdr, messageID)
			setIntegrationAuthority(message, testConfigVersionID)
			message.Data = marshalAccessEnvelope(t, messageID, now, []AccessEvent{event})
			mutate(message)
			ack, err := jetstream.PublishMsg(message)
			if err != nil || ack == nil || ack.Stream != config.Stream {
				t.Fatalf("publish malformed authority ack=%+v err=%v", ack, err)
			}
			deliveries, err := consumer.Fetch(context.Background())
			if err != nil || len(deliveries) != 1 {
				t.Fatalf("fetch malformed authority deliveries=%d err=%v", len(deliveries), err)
			}
			rawDelivery := deliveries[0].(*natsIngestDelivery)
			originalHeaders := make(nats.Header, len(rawDelivery.message.Header))
			for key, values := range rawDelivery.message.Header {
				originalHeaders[key] = append([]string(nil), values...)
			}
			processor := mustProcessor(t, now, &fakeIngestWriter{}, sink, IngestProcessorConfig{
				OperationTimeout: 5 * time.Second,
			})
			result, err := processor.Process(context.Background(), deliveries)
			if err != nil || result.Terminated != 1 || result.Naked != 0 || result.Acknowledged != 0 {
				t.Fatalf("malformed authority was not finitely isolated: result=%+v err=%v", result, err)
			}
			if replayed, fetchErr := consumer.Fetch(context.Background()); !errors.Is(fetchErr, ErrNoIngestMessages) || len(replayed) != 0 {
				t.Fatalf("malformed authority redelivered after terminal isolation: deliveries=%d err=%v", len(replayed), fetchErr)
			}

			info, err := jetstream.StreamInfo(config.IsolationStream)
			if err != nil || info.State.Msgs != 1 {
				t.Fatalf("isolation stream state=%+v err=%v", info, err)
			}
			stored, err := jetstream.GetMsg(config.IsolationStream, info.State.FirstSeq)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(stored.Data, message.Data) || bytes.Contains(stored.Data, []byte("must-remain-encrypted")) {
				t.Fatal("malformed authority evidence leaked plaintext wire")
			}
			record, wire := decryptOBSUsageAIsolationEvidence(t, sink, stored.Data)
			if record.Subject != message.Subject || wire.Subject != message.Subject || !bytes.Equal(wire.Payload, message.Data) {
				t.Fatalf("isolated evidence did not preserve subject/payload: record=%+v wire=%+v", record, wire)
			}
			replayedHeaders := make(nats.Header)
			for _, header := range wire.Headers {
				replayedHeaders.Add(header.Name, header.Value)
			}
			if !reflect.DeepEqual(replayedHeaders, originalHeaders) {
				t.Fatalf("isolated evidence did not preserve exact headers: got=%v want=%v", replayedHeaders, originalHeaders)
			}
			if _, err := sink.Replay(stored.Data); err == nil {
				t.Fatal("malformed authority isolation wire was replayed as trusted ingest")
			}
		})
	}
}
