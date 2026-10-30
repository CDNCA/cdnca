//go:build integration

package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type failParkedDeleteKeyValue struct {
	nats.KeyValue
	mu        sync.Mutex
	remaining int
}

type failRecreateJetStream struct {
	nats.JetStreamContext
	entered chan struct{}
	once    sync.Once
}

func (jetstream *failRecreateJetStream) ConsumerInfo(string, string, ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	return nil, nats.ErrConsumerNotFound
}

func (jetstream *failRecreateJetStream) AddConsumer(string, *nats.ConsumerConfig, ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	jetstream.once.Do(func() { close(jetstream.entered) })
	return nil, errors.New("injected recreate retry")
}

func (value *failParkedDeleteKeyValue) Delete(key string, options ...nats.DeleteOpt) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	if strings.HasPrefix(key, "parked.") && value.remaining > 0 {
		value.remaining--
		return errors.New("injected parked marker delete failure")
	}
	return value.KeyValue.Delete(key, options...)
}

func TestOBSUsageARound6PubAckCrashReconcilesExactEvidenceAfterDedupExpiry(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.DuplicateWindow = 100 * time.Millisecond
	config.AckWait = 10 * time.Second
	config.OperationTimeout = 2 * time.Second
	config.FetchTimeout = 500 * time.Millisecond
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round6MalformedDelivery(t, connection, jetstream, config, "puback-crash")
	record := isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC())
	intent, err := sink.prepareTerminalEvidence(context.Background(), delivery, record)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := sink.publishEvidenceIntent(context.Background(), intent)
	if err != nil || sequence == 0 {
		if info, infoErr := jetstream.StreamInfo(config.IsolationStream); infoErr == nil && info.State.Msgs > 0 {
			if stored, getErr := jetstream.GetMsg(config.IsolationStream, info.State.FirstSeq); getErr == nil {
				t.Logf("stored subject=%q sequence=%d headers=%v data_sha=%x intent_sha=%x data_equal=%t",
					stored.Subject, stored.Sequence, stored.Header, sha256Sum(stored.Data), intent.PayloadSHA256,
					bytes.Equal(stored.Data, intent.Payload))
			}
		}
		t.Fatalf("publish evidence sequence=%d err=%v", sequence, err)
	}
	entry, err := consumer.stateStore.Get(parkedStateKey(delivery.streamSequence))
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
	if err != nil || state.Phase != parkedPhaseEvidencePrepared || state.EvidenceConfirmed {
		t.Fatalf("pre-confirm crash marker=%+v err=%v", state, err)
	}
	time.Sleep(2 * config.DuplicateWindow)
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	replayed := round6WaitDelivery(t, restarted, 3*config.AckWait)
	if _, prepareErr := sink.prepareTerminalEvidence(
		context.Background(), replayed.(*natsIngestDelivery),
		isolationRecord(replayed, RejectInvalidJSON, time.Now().UTC()),
	); prepareErr != nil {
		t.Fatalf("restart could not rebuild persisted evidence intent: %v", prepareErr)
	}
	processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, sink, IngestProcessorConfig{
		OperationTimeout: 10 * time.Second,
	})
	result, err := processor.Process(context.Background(), []IngestDelivery{replayed})
	if err != nil || result.Terminated != 1 || result.Naked != 0 {
		t.Fatalf("restart result=%+v err=%v", result, err)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != 1 || info.State.FirstSeq != sequence {
		t.Fatalf("reconciled evidence state=%+v original_sequence=%d err=%v", info, sequence, err)
	}
	entry, err = restarted.stateStore.Get(parkedStateKey(replayed.StreamSequence()))
	if err != nil {
		t.Fatalf("settled marker was not retained: %v", err)
	}
	state, err = decodeParkedDeliveryState(entry.Value(), replayed.StreamSequence())
	if err != nil || state.Phase != parkedPhaseSettled || !state.TermSent {
		t.Fatalf("retained settled marker=%+v err=%v", state, err)
	}
}

func TestOBSUsageARound6UnknownPublishAckReconcilesForwardAndReverse(t *testing.T) {
	for _, publishBeforeError := range []bool{true, false} {
		t.Run(fmt.Sprintf("published=%t", publishBeforeError), func(t *testing.T) {
			connection, jetstream := connectJetStreamBlockerProof(t)
			config := obsUsageAJetStreamConfig()
			config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
			config.AckWait = 10 * time.Second
			config.OperationTimeout = 2 * time.Second
			config.FetchTimeout = 500 * time.Millisecond
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
				t.Fatal(err)
			}
			consumer, sink, delivery := round6MalformedDelivery(t, connection, jetstream, config, "unknown-ack")
			realPublish := sink.jetstream.PublishMsg
			sink.publishMessage = func(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
				if publishBeforeError {
					if _, err := realPublish(message, options...); err != nil {
						return nil, err
					}
				}
				return nil, context.DeadlineExceeded
			}
			processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, sink, IngestProcessorConfig{
				OperationTimeout: 10 * time.Second,
			})
			result, processErr := processor.Process(context.Background(), []IngestDelivery{delivery})
			if publishBeforeError {
				if processErr != nil || result.Terminated != 1 || result.Naked != 0 {
					t.Fatalf("forward reconciliation result=%+v err=%v", result, processErr)
				}
			} else {
				if processErr == nil || result.Naked != 1 || result.Terminated != 0 {
					t.Fatalf("reverse uncertainty result=%+v err=%v", result, processErr)
				}
				sink.publishMessage = nil
				replayed := round6WaitDelivery(t, consumer, 3*config.AckWait)
				result, processErr = processor.Process(context.Background(), []IngestDelivery{replayed})
				if processErr != nil || result.Terminated != 1 || result.Naked != 0 {
					t.Fatalf("reverse retry result=%+v err=%v", result, processErr)
				}
			}
			info, err := jetstream.StreamInfo(config.IsolationStream)
			if err != nil || info.State.Msgs != 1 {
				t.Fatalf("unknown ACK evidence state=%+v err=%v", info, err)
			}
			_ = consumer.Close()
		})
	}
}

func TestOBSUsageARound6DuplicatePubAckRejectsSameMessageIDWrongEvidence(t *testing.T) {
	for _, mutation := range []string{"wire", "headers"} {
		t.Run(mutation, func(t *testing.T) {
			connection, jetstream := connectJetStreamBlockerProof(t)
			config := obsUsageAJetStreamConfig()
			config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
			config.AckWait = 10 * time.Second
			config.OperationTimeout = 2 * time.Second
			config.FetchTimeout = 500 * time.Millisecond
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
				t.Fatal(err)
			}
			consumer, sink, delivery := round6MalformedDelivery(t, connection, jetstream, config, "wrong-evidence-"+mutation)
			defer consumer.Close()
			intent, err := sink.prepareTerminalEvidence(
				context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
			)
			if err != nil {
				t.Fatal(err)
			}
			wrong := nats.NewMsg(intent.Subject)
			wrong.Data = append([]byte(nil), intent.Payload...)
			wrong.Header.Set(nats.MsgIdHdr, intent.MessageID)
			if mutation == "wire" {
				wrong.Data = append(wrong.Data, 'x')
			} else {
				wrong.Header.Set("X-Extra", "wrong")
			}
			ack, err := jetstream.PublishMsg(wrong)
			if err != nil || ack == nil || ack.Stream != config.IsolationStream || ack.Sequence == 0 {
				t.Fatalf("publish wrong evidence ack=%+v err=%v", ack, err)
			}
			if sequence, err := sink.publishEvidenceIntent(context.Background(), intent); err == nil || sequence != 0 {
				t.Fatalf("same Msg-Id wrong %s was accepted: sequence=%d err=%v", mutation, sequence, err)
			}
			info, err := jetstream.StreamInfo(config.IsolationStream)
			if err != nil || info.State.Msgs != 1 {
				t.Fatalf("wrong evidence changed stream state=%+v err=%v", info, err)
			}
		})
	}
}

func TestOBSUsageARound6SettlementDeleteFailureIsRecoveredAndBounded(t *testing.T) {
	for _, settlement := range []string{"ack", "term"} {
		t.Run(settlement, func(t *testing.T) {
			connection, jetstream := connectJetStreamBlockerProof(t)
			config := obsUsageAJetStreamConfig()
			config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
			config.AckWait = 10 * time.Second
			config.OperationTimeout = 2 * time.Second
			config.FetchTimeout = 500 * time.Millisecond
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
				t.Fatal(err)
			}
			consumer, sink, delivery := round6MalformedDelivery(t, connection, jetstream, config, "delete-failure-"+settlement)
			realStore := consumer.stateStore
			consumer.stateStore = &failParkedDeleteKeyValue{KeyValue: realStore, remaining: 8}
			var settleErr error
			if settlement == "ack" {
				settleErr = delivery.Ack(context.Background())
			} else {
				processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, sink, IngestProcessorConfig{
					OperationTimeout: 10 * time.Second,
				})
				_, settleErr = processor.Process(context.Background(), []IngestDelivery{delivery})
			}
			if settlement == "ack" && (settleErr == nil || !strings.Contains(settleErr.Error(), "delete failure")) {
				t.Fatalf("ack did not surface marker deletion uncertainty: %v", settleErr)
			}
			if settlement == "term" && settleErr != nil {
				t.Fatalf("term depended on forbidden marker deletion: %v", settleErr)
			}
			keys, err := realStore.Keys()
			if err != nil || round6ParkedKeyCount(keys) != 1 {
				t.Fatalf("unbounded marker state keys=%v err=%v", keys, err)
			}
			for attempt := 0; settlement == "ack" && attempt < 2; attempt++ {
				if deliveries, fetchErr := consumer.Fetch(context.Background()); fetchErr == nil || len(deliveries) != 0 ||
					!strings.Contains(fetchErr.Error(), "delete failure") {
					t.Fatalf("reconciliation failure %d deliveries=%d err=%v", attempt+1, len(deliveries), fetchErr)
				}
				keys, err = realStore.Keys()
				if err != nil || round6ParkedKeyCount(keys) != 1 {
					t.Fatalf("reconciliation failure %d grew marker state keys=%v err=%v", attempt+1, keys, err)
				}
			}
			consumer.stateStore = realStore
			if err := consumer.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewNATSIngestConsumer(connection, config)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			if deliveries, fetchErr := restarted.Fetch(context.Background()); !errors.Is(fetchErr, ErrNoIngestMessages) || len(deliveries) != 0 {
				t.Fatalf("%s settled message replayed after GC: deliveries=%d err=%v", settlement, len(deliveries), fetchErr)
			}
			_, markerErr := realStore.Get(parkedStateKey(delivery.StreamSequence()))
			if settlement == "ack" && !errors.Is(markerErr, nats.ErrKeyNotFound) {
				t.Fatalf("ack restart did not GC marker: %v", markerErr)
			}
			if settlement == "term" && markerErr != nil {
				t.Fatalf("term restart lost retained marker: %v", markerErr)
			}
		})
	}
}

func TestOBSUsageARound7ConditionalPublishLinearizesAfterDedupExpiry(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.DuplicateWindow = 100 * time.Millisecond
	config.OperationTimeout = 2 * time.Second
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "conditional-publish-r7")
	defer consumer.Close()
	intent, err := sink.prepareTerminalEvidence(
		context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
	)
	if err != nil {
		t.Fatal(err)
	}
	realPublish := sink.jetstream.PublishMsg
	var once sync.Once
	sink.publishMessage = func(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
		once.Do(func() {
			delayed := nats.NewMsg(message.Subject)
			delayed.Data = append([]byte(nil), message.Data...)
			for name, values := range message.Header {
				delayed.Header[name] = append([]string(nil), values...)
			}
			if _, publishErr := realPublish(
				delayed, nats.ExpectStream(config.IsolationStream), nats.ExpectLastSequence(intent.ScanLast),
			); publishErr != nil {
				t.Fatalf("publish delayed original evidence: %v", publishErr)
			}
			time.Sleep(2 * config.DuplicateWindow)
		})
		return realPublish(message, options...)
	}
	sequence, err := sink.publishEvidenceIntent(context.Background(), intent)
	if err != nil || sequence == 0 {
		if info, infoErr := jetstream.StreamInfo(config.IsolationStream); infoErr == nil {
			for storedSequence := info.State.FirstSeq; storedSequence <= info.State.LastSeq && storedSequence != 0; storedSequence++ {
				if stored, getErr := jetstream.GetMsg(config.IsolationStream, storedSequence); getErr == nil {
					t.Logf("stored evidence sequence=%d header_names=%v", stored.Sequence, round7HeaderNames(stored.Header))
				}
			}
		}
		t.Fatalf("conditional evidence sequence=%d err=%v", sequence, err)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != 1 || info.State.FirstSeq != sequence || info.State.LastSeq != sequence {
		t.Fatalf("conditional publish accepted duplicate state=%+v sequence=%d err=%v", info, sequence, err)
	}
}

func TestOBSUsageARound7EvidenceHoleWithSourceReturnsToPreparedIntent(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.DuplicateWindow = 100 * time.Millisecond
	config.OperationTimeout = 5 * time.Second
	config.AckWait = 25 * time.Second
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "source-present-hole-r7")
	defer consumer.Close()
	initialIntent, evidenceSequence := round7ConfirmEvidence(t, sink, delivery)
	if err := jetstream.DeleteMsg(config.IsolationStream, evidenceSequence); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * config.DuplicateWindow)
	confirmed, err := delivery.TerminalEvidenceConfirmed(context.Background())
	if err != nil || confirmed {
		t.Fatalf("source-present evidence hole confirmed=%t err=%v", confirmed, err)
	}
	entry, err := consumer.stateStore.Get(parkedStateKey(delivery.streamSequence))
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
	if err != nil || state.Phase != parkedPhaseEvidencePrepared || state.EvidenceConfirmed || state.EvidenceSequence != 0 {
		t.Fatalf("source-present evidence hole state=%+v err=%v", state, err)
	}
	if state.EvidenceGeneration != 0 || state.EvidenceMessageID != initialIntent.MessageID {
		t.Fatalf("source-present evidence retry identity=%+v initial=%s", state, initialIntent.MessageID)
	}
	processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, sink, IngestProcessorConfig{
		OperationTimeout: 10 * time.Second,
	})
	result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
	for attempt := 0; err != nil && attempt < 6; attempt++ {
		if result.Naked > 1 || result.Terminated != 0 {
			t.Fatalf("source-present evidence checkpoint result=%+v err=%v", result, err)
		}
		entry, stateErr := consumer.stateStore.Get(parkedStateKey(delivery.streamSequence))
		if stateErr != nil {
			t.Fatal(stateErr)
		}
		state, stateErr = decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if stateErr != nil || state.Phase != parkedPhaseEvidencePrepared || state.EvidenceConfirmed {
			t.Fatalf("source-present evidence retry state=%+v err=%v", state, stateErr)
		}
		replayed := round6WaitDelivery(t, consumer, 3*config.AckWait)
		result, err = processor.Process(context.Background(), []IngestDelivery{replayed})
	}
	if err != nil || result.Terminated != 1 || result.Naked != 0 {
		t.Fatalf("source-present evidence repair result=%+v err=%v", result, err)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("repaired evidence state=%+v err=%v", info, err)
	}
}

func TestOBSUsageARound7SourceGoneEvidenceHoleRetainsCrashProof(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.OperationTimeout = 5 * time.Second
	config.AckWait = 25 * time.Second
	config.FetchTimeout = 300 * time.Millisecond
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "source-gone-hole-r7")
	_, evidenceSequence := round7ConfirmEvidence(t, sink, delivery)
	key := parkedStateKey(delivery.streamSequence)
	entry, err := consumer.stateStore.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
	if err != nil {
		t.Fatal(err)
	}
	state.Phase = parkedPhaseTermPending
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.stateStore.Update(key, encoded, entry.Revision()); err != nil {
		t.Fatal(err)
	}
	if err := jetstream.DeleteMsg(config.Stream, delivery.streamSequence); err != nil {
		t.Fatal(err)
	}
	if err := jetstream.DeleteMsg(config.IsolationStream, evidenceSequence); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if deliveries, fetchErr := restarted.Fetch(context.Background()); fetchErr == nil || len(deliveries) != 0 {
		t.Fatalf("source-gone evidence hole was treated as settled: deliveries=%d err=%v", len(deliveries), fetchErr)
	}
	retained, err := restarted.stateStore.Get(key)
	if err != nil {
		t.Fatalf("source-gone evidence proof was deleted: %v", err)
	}
	retainedState, err := decodeParkedDeliveryState(retained.Value(), delivery.streamSequence)
	if err != nil || retainedState.Phase != parkedPhaseTermPending || !retainedState.EvidenceConfirmed {
		t.Fatalf("retained source-gone proof=%+v err=%v", retainedState, err)
	}
}

func TestOBSUsageARound7IsolationScanIsFixedBoundedAndRestartable(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.StreamMaxMessages = 1000
	config.IsolationMaxBytes = 16 << 20
	config.OperationTimeout = 5 * time.Second
	config.AckWait = 25 * time.Second
	config.FetchTimeout = 300 * time.Millisecond
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	const deepMessages = 96
	for index := 0; index < deepMessages; index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("unrelated-r7-%03d", index))
		message.Data = []byte("unrelated")
		if _, err := jetstream.PublishMsg(message, nats.ExpectStream(config.IsolationStream)); err != nil {
			t.Fatal(err)
		}
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "deep-scan-r7")
	processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, sink, IngestProcessorConfig{
		OperationTimeout: 10 * time.Second,
	})
	first, firstErr := processor.Process(context.Background(), []IngestDelivery{delivery})
	if firstErr == nil || first.Naked > 1 || first.Terminated != 0 {
		t.Fatalf("deep scan consumed an unbounded fetch step result=%+v err=%v", first, firstErr)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 1; sequence++ {
		if err := jetstream.DeleteMsg(config.IsolationStream, sequence); err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
			t.Fatal(err)
		}
	}
	for sequence := uint64(3); sequence < deepMessages; sequence += 3 {
		if err := jetstream.DeleteMsg(config.IsolationStream, sequence); err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
			t.Fatal(err)
		}
	}
	restarted, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	for attempt := 0; attempt < 12; attempt++ {
		replayed := round6WaitDelivery(t, restarted, 3*config.AckWait)
		result, processErr := processor.Process(context.Background(), []IngestDelivery{replayed})
		if processErr == nil && result.Terminated == 1 {
			info, infoErr := jetstream.StreamInfo(config.IsolationStream)
			if infoErr != nil || info.State.FirstSeq <= 1 {
				t.Fatalf("isolation FirstSeq did not move across recovery: state=%+v err=%v", info, infoErr)
			}
			return
		}
		if processErr == nil || result.Naked > 1 || result.Terminated != 0 {
			t.Fatalf("restart scan attempt=%d result=%+v err=%v", attempt+1, result, processErr)
		}
	}
	t.Fatal("bounded evidence scan did not resume to completion")
}

func TestOBSUsageARound7FetchPreCancellationDoesNotMutateLease(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if deliveries, fetchErr := consumer.Fetch(cancelled); !errors.Is(fetchErr, context.Canceled) || len(deliveries) != 0 {
		t.Fatalf("pre-cancelled Fetch deliveries=%d err=%v", len(deliveries), fetchErr)
	}
	if _, err := consumer.leaseStore.Get("active"); !errors.Is(err, nats.ErrKeyNotFound) {
		t.Fatalf("pre-cancelled Fetch mutated lease: %v", err)
	}
}

func TestOBSUsageARound7CloseCancelsConsumerRecoveryPromptly(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.OperationTimeout = 500 * time.Millisecond
	config.FetchTimeout = 200 * time.Millisecond
	config.AckWait = 3 * time.Second
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
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
	recovery := consumerRecoveryState{
		SchemaVersion: 1, Phase: recoveryPrepared, OwnerID: consumer.ownerID,
		StreamCreated:         streamInfo.Created.UTC().Format(time.RFC3339Nano),
		SourceConsumerCreated: consumerInfo.Created.UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(recovery)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.stateStore.Create(consumerRecoveryStateKey, encoded); err != nil {
		t.Fatal(err)
	}
	failing := &failRecreateJetStream{JetStreamContext: consumer.jetstream, entered: make(chan struct{})}
	consumer.jetstream = failing
	fetchDone := make(chan error, 1)
	go func() {
		_, fetchErr := consumer.Fetch(context.Background())
		fetchDone <- fetchErr
	}()
	select {
	case <-failing.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("consumer recreation did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- consumer.Close() }()
	select {
	case err := <-closeDone:
		if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
			t.Fatalf("Close error=%v", err)
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("Close did not cancel in-flight consumer recreation promptly")
	}
	select {
	case err := <-fetchDone:
		if err == nil {
			t.Fatal("cancelled recovery Fetch returned nil")
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("cancelled recovery Fetch did not return promptly")
	}
}

type round8RecordingJetStream struct {
	nats.JetStreamContext
	mu        sync.Mutex
	sequences []uint64
}

func (jetstream *round8RecordingJetStream) GetMsg(
	stream string,
	sequence uint64,
	options ...nats.JSOpt,
) (*nats.RawStreamMsg, error) {
	jetstream.mu.Lock()
	jetstream.sequences = append(jetstream.sequences, sequence)
	jetstream.mu.Unlock()
	return jetstream.JetStreamContext.GetMsg(stream, sequence, options...)
}

func (jetstream *round8RecordingJetStream) snapshot() []uint64 {
	jetstream.mu.Lock()
	defer jetstream.mu.Unlock()
	return append([]uint64(nil), jetstream.sequences...)
}

type round8PostBindDriftJetStream struct {
	nats.JetStreamContext
	mu           sync.Mutex
	pulled       bool
	subscription *nats.Subscription
}

func (jetstream *round8PostBindDriftJetStream) PullSubscribe(
	subject string,
	durable string,
	options ...nats.SubOpt,
) (*nats.Subscription, error) {
	subscription, err := jetstream.JetStreamContext.PullSubscribe(subject, durable, options...)
	jetstream.mu.Lock()
	jetstream.pulled = err == nil
	jetstream.subscription = subscription
	jetstream.mu.Unlock()
	return subscription, err
}

func (jetstream *round8PostBindDriftJetStream) ConsumerInfo(
	stream string,
	consumer string,
	options ...nats.JSOpt,
) (*nats.ConsumerInfo, error) {
	info, err := jetstream.JetStreamContext.ConsumerInfo(stream, consumer, options...)
	jetstream.mu.Lock()
	pulled := jetstream.pulled
	jetstream.mu.Unlock()
	if err != nil || !pulled {
		return info, err
	}
	drifted := *info
	drifted.Config = info.Config
	drifted.Config.MaxWaiting++
	return &drifted, nil
}

type round8DelayedPullJetStream struct {
	nats.JetStreamContext
	entered      chan struct{}
	release      chan struct{}
	once         sync.Once
	mu           sync.Mutex
	subscription *nats.Subscription
}

func (jetstream *round8DelayedPullJetStream) PullSubscribe(
	subject string,
	durable string,
	options ...nats.SubOpt,
) (*nats.Subscription, error) {
	subscription, err := jetstream.JetStreamContext.PullSubscribe(subject, durable, options...)
	if err != nil {
		return nil, err
	}
	jetstream.mu.Lock()
	jetstream.subscription = subscription
	jetstream.mu.Unlock()
	jetstream.once.Do(func() { close(jetstream.entered) })
	<-jetstream.release
	return subscription, nil
}

func TestOBSUsageARound8RuntimeOpenRejectsStreamDriftAndAcceptsExactConfig(t *testing.T) {
	for _, target := range []string{"ingest", "isolation"} {
		t.Run(target, func(t *testing.T) {
			connection, jetstream := connectRound7JetStream(t)
			config := obsUsageAJetStreamConfig()
			config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
				t.Fatal(err)
			}
			stream := config.Stream
			if target == "isolation" {
				stream = config.IsolationStream
			}
			info, err := jetstream.StreamInfo(stream)
			if err != nil {
				t.Fatal(err)
			}
			drifted := info.Config
			drifted.MaxBytes--
			if _, err := jetstream.UpdateStream(&drifted); err != nil {
				t.Fatal(err)
			}
			consumer, consumerErr := NewNATSIngestConsumer(connection, config)
			if consumerErr == nil {
				_ = consumer.Close()
				t.Fatalf("runtime consumer accepted %s stream drift", target)
			}
			if target == "isolation" {
				if sink, sinkErr := NewNATSIsolationSink(connection, config); sinkErr == nil || sink != nil {
					t.Fatalf("runtime isolation sink accepted stream drift: sink=%+v err=%v", sink, sinkErr)
				}
			}
		})
	}

	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatalf("exact runtime consumer config rejected: %v", err)
	}
	defer consumer.Close()
	if sink, err := NewNATSIsolationSink(connection, config); err != nil || sink == nil {
		t.Fatalf("exact runtime isolation config rejected: sink=%+v err=%v", sink, err)
	}
}

func TestOBSUsageARound8PostBindConsumerDriftFailsClosed(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	if err := consumer.unbindSubscription(); err != nil {
		t.Fatal(err)
	}
	drifted := &round8PostBindDriftJetStream{JetStreamContext: consumer.jetstream}
	consumer.jetstream = drifted
	if err := consumer.bindSubscription(); err == nil {
		t.Fatal("post-bind consumer drift was accepted")
	}
	consumer.mu.Lock()
	installed := consumer.subscription
	consumer.mu.Unlock()
	drifted.mu.Lock()
	local := drifted.subscription
	drifted.mu.Unlock()
	if installed != nil || local == nil || local.IsValid() {
		t.Fatalf("drifted bind leaked subscription: installed=%v local=%v valid=%t", installed != nil, local != nil, local != nil && local.IsValid())
	}
}

func TestOBSUsageARound8DelayedBindCannotInstallAfterClose(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.unbindSubscription(); err != nil {
		t.Fatal(err)
	}
	delayed := &round8DelayedPullJetStream{
		JetStreamContext: consumer.jetstream, entered: make(chan struct{}), release: make(chan struct{}),
	}
	consumer.jetstream = delayed
	bindDone := make(chan error, 1)
	go func() { bindDone <- consumer.bindSubscription() }()
	select {
	case <-delayed.entered:
	case <-time.After(3 * time.Second):
		close(delayed.release)
		t.Fatal("delayed bind did not reach post-PullSubscribe barrier")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- consumer.Close() }()
	select {
	case err := <-closeDone:
		if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
			close(delayed.release)
			t.Fatalf("Close error=%v", err)
		}
	case <-time.After(time.Second):
		close(delayed.release)
		t.Fatal("Close waited for a bind handle it had not installed")
	}
	close(delayed.release)
	if err := <-bindDone; err == nil {
		t.Fatal("bind racing Close returned success")
	}
	consumer.mu.Lock()
	installed := consumer.subscription
	consumer.mu.Unlock()
	delayed.mu.Lock()
	local := delayed.subscription
	delayed.mu.Unlock()
	if installed != nil || local == nil || local.IsValid() {
		t.Fatalf("post-Close bind leaked subscription: installed=%v local=%v valid=%t", installed != nil, local != nil, local != nil && local.IsValid())
	}
	if err := consumer.Close(); err != nil {
		t.Fatalf("idempotent Close error=%v", err)
	}
}

func TestOBSUsageARound8DeepTailTerminatesWithFixedBudgetAndDefaultBackoff(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	defaults := DefaultJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.StreamMaxMessages = defaults.StreamMaxMessages
	config.NakBaseDelay = defaults.NakBaseDelay
	config.NakMaxDelay = defaults.NakMaxDelay
	config.AckWait = 15 * time.Second
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	const deepMessages = 96
	for index := 0; index < deepMessages; index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round8-deep-%03d", index))
		message.Data = []byte("unrelated")
		if _, err := jetstream.PublishMsg(message, nats.ExpectStream(config.IsolationStream)); err != nil {
			t.Fatal(err)
		}
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round8-deep-tail")
	defer consumer.Close()
	processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, sink, IngestProcessorConfig{
		OperationTimeout: 10 * time.Second, NakBaseDelay: defaults.NakBaseDelay, NakMaxDelay: defaults.NakMaxDelay,
	})
	current := IngestDelivery(delivery)
	for attempt := 0; attempt < 3; attempt++ {
		result, processErr := processor.Process(context.Background(), []IngestDelivery{current})
		if processErr == nil && result.Terminated == 1 && result.Naked == 0 {
			info, infoErr := jetstream.StreamInfo(config.IsolationStream)
			if infoErr != nil || info.State.Msgs != deepMessages+1 {
				t.Fatalf("deep-tail evidence state=%+v err=%v", info, infoErr)
			}
			return
		}
		if processErr == nil || result.Naked != 1 || result.Terminated != 0 {
			t.Fatalf("deep-tail attempt=%d result=%+v err=%v", attempt+1, result, processErr)
		}
		current = round6WaitDelivery(t, consumer, 12*time.Second)
	}
	t.Fatal("96-message deep-tail scan did not terminate within the fixed batch budget")
}

func TestOBSUsageARound8RecordWithoutDeliveryResumesDurableScanProgress(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.StreamMaxMessages = DefaultJetStreamConfig().StreamMaxMessages
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	const deepMessages = 96
	for index := 0; index < deepMessages; index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round8-record-%03d", index))
		message.Data = []byte("unrelated")
		if _, err := jetstream.PublishMsg(message, nats.ExpectStream(config.IsolationStream)); err != nil {
			t.Fatal(err)
		}
	}
	record := reviewerIsolationRecord("round8-record-resume", "round8-sensitive-wire")
	first, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	firstRecorder := &round8RecordingJetStream{JetStreamContext: first.jetstream}
	first.jetstream = firstRecorder
	if err := first.Record(context.Background(), record); !errors.Is(err, errIsolationEvidenceScanPending) {
		t.Fatalf("first bounded Record error=%v", err)
	}
	firstSequences := firstRecorder.snapshot()
	if len(firstSequences) < 2 || len(firstSequences) >= deepMessages {
		t.Fatalf("first Record scan was not a fixed multi-message batch: sequences=%v", firstSequences)
	}

	restarted, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	restartedRecorder := &round8RecordingJetStream{JetStreamContext: restarted.jetstream}
	restarted.jetstream = restartedRecorder
	if err := restarted.Record(context.Background(), record); err != nil {
		t.Fatalf("restarted Record did not finish from durable progress: %v", err)
	}
	restartedSequences := restartedRecorder.snapshot()
	if len(restartedSequences) == 0 || restartedSequences[0] <= firstSequences[len(firstSequences)-1] {
		t.Fatalf("restarted Record rescanned from the beginning: first=%v restarted=%v", firstSequences, restartedSequences)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != deepMessages+1 {
		t.Fatalf("restart-safe Record state=%+v err=%v", info, err)
	}
}

func TestOBSUsageARound9DeepRecoveryProgressesWithoutBrokerRedelivery(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	defaults := DefaultJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.StreamMaxMessages = defaults.StreamMaxMessages
	config.NakBaseDelay = defaults.NakBaseDelay
	config.NakMaxDelay = defaults.NakMaxDelay
	config.AckWait = 20 * time.Second
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}

	defaultBatches := (defaults.StreamMaxMessages + int64(isolationEvidenceScanBatch) - 1) /
		int64(isolationEvidenceScanBatch)
	var nakOnlyDelay time.Duration
	for attempt := int64(1); attempt < defaultBatches; attempt++ {
		nakOnlyDelay += boundedNakDelay(uint64(attempt), defaults.NakBaseDelay, defaults.NakMaxDelay)
	}
	if nakOnlyDelay < 200*24*time.Hour {
		t.Fatalf("default-capacity NAK-only formula unexpectedly operational: batches=%d delay=%s", defaultBatches, nakOnlyDelay)
	}

	const deepMessages = 2048
	for index := 0; index < deepMessages; index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round9-deep-%05d", index))
		message.Data = []byte("unrelated")
		if _, err := jetstream.PublishMsg(message, nats.ExpectStream(config.IsolationStream)); err != nil {
			t.Fatal(err)
		}
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round9-independent-recovery")
	defer consumer.Close()
	processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, sink, IngestProcessorConfig{
		OperationTimeout: 10 * time.Second, NakBaseDelay: defaults.NakBaseDelay, NakMaxDelay: defaults.NakMaxDelay,
	})
	result, processErr := processor.Process(context.Background(), []IngestDelivery{delivery})
	if processErr == nil || result.Naked != 1 || result.Terminated != 0 {
		t.Fatalf("initial independent recovery result=%+v err=%v", result, processErr)
	}

	key := parkedStateKey(delivery.streamSequence)
	deadline := time.Now().Add(15 * time.Second)
	for {
		entry, err := consumer.stateStore.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
		if err != nil {
			t.Fatal(err)
		}
		if state.EvidenceConfirmed {
			if state.EvidenceScanStart <= isolationEvidenceScanBatch {
				t.Fatalf("deep recovery did not advance beyond one inner batch: state=%+v", state)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deep recovery remained dependent on broker redelivery: state=%+v", state)
		}
		time.Sleep(10 * time.Millisecond)
	}

	replayed := round6WaitDelivery(t, consumer, 10*time.Second)
	result, processErr = processor.Process(context.Background(), []IngestDelivery{replayed})
	if processErr != nil || result.Terminated != 1 || result.Naked != 0 {
		t.Fatalf("independently recovered delivery result=%+v err=%v", result, processErr)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != deepMessages+1 {
		t.Fatalf("independent recovery evidence state=%+v err=%v", info, err)
	}
}

func TestOBSUsageARound9IsolationCursorResetsAcrossRepeatedStreamEpochs(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.StreamMaxMessages = DefaultJetStreamConfig().StreamMaxMessages
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	record := reviewerIsolationRecord("round9-epoch-reset", "round9-epoch-sensitive-wire")
	for index := 0; index < 192; index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round9-old-epoch-%03d", index))
		message.Data = []byte("old")
		if _, err := jetstream.PublishMsg(message); err != nil {
			t.Fatal(err)
		}
	}
	sink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(context.Background(), record); !errors.Is(err, errIsolationEvidenceScanPending) {
		t.Fatalf("old-epoch cursor setup error=%v", err)
	}

	for epoch, messages := range []int{129, 257} {
		if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
			t.Fatal(err)
		}
		if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < messages; index++ {
			message := nats.NewMsg(IsolationSubject)
			message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round9-epoch-%d-%03d", epoch+1, index))
			message.Data = []byte("current")
			if _, err := jetstream.PublishMsg(message); err != nil {
				t.Fatal(err)
			}
		}
		if err := jetstream.DeleteMsg(config.IsolationStream, 1); err != nil {
			t.Fatal(err)
		}
		for sequence := uint64(7); sequence < uint64(messages); sequence += 17 {
			if err := jetstream.DeleteMsg(config.IsolationStream, sequence); err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
				t.Fatal(err)
			}
		}
		sink, err = NewNATSIsolationSink(connection, config)
		if err != nil {
			t.Fatal(err)
		}
		if epoch == 0 {
			if err := sink.Record(context.Background(), record); err != nil && !errors.Is(err, errIsolationEvidenceScanPending) {
				t.Fatalf("first epoch reset error=%v", err)
			}
		}
	}

	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil {
		t.Fatal(err)
	}
	wantMessages := info.State.Msgs + 1
	first, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	errorsBySink := make(chan error, 2)
	for _, candidate := range []*NATSIsolationSink{first, second} {
		candidate := candidate
		go func() {
			for attempt := 0; attempt < 16; attempt++ {
				err := candidate.Record(context.Background(), record)
				if err == nil {
					errorsBySink <- nil
					return
				}
				if !errors.Is(err, errIsolationEvidenceScanPending) && !errors.Is(err, nats.ErrKeyExists) {
					errorsBySink <- err
					return
				}
			}
			errorsBySink <- errors.New("epoch recovery did not complete within bounded attempts")
		}()
	}
	for range 2 {
		if err := <-errorsBySink; err != nil {
			t.Fatal(err)
		}
	}
	info, err = jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != wantMessages {
		t.Fatalf("concurrent epoch recovery state=%+v want_messages=%d err=%v", info, wantMessages, err)
	}
}

func TestOBSUsageARound9RecreateDuringConditionalPublishResetsBeforeRetry(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.StreamMaxMessages = DefaultJetStreamConfig().StreamMaxMessages
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	record := reviewerIsolationRecord("round9-publish-epoch", "round9-publish-sensitive-wire")
	for index := 0; index < 128; index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round9-pre-publish-%03d", index))
		message.Data = []byte("old")
		if _, err := jetstream.PublishMsg(message); err != nil {
			t.Fatal(err)
		}
	}
	sink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(context.Background(), record); !errors.Is(err, errIsolationEvidenceScanPending) {
		t.Fatalf("initial conditional scan error=%v", err)
	}
	realPublish := sink.jetstream.PublishMsg
	var recreateOnce sync.Once
	sink.publishMessage = func(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
		var recreateErr error
		recreateOnce.Do(func() {
			if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
				recreateErr = err
				return
			}
			if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
				recreateErr = err
				return
			}
			for index := 0; index < 7; index++ {
				unrelated := nats.NewMsg(IsolationSubject)
				unrelated.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round9-new-epoch-%d", index))
				unrelated.Data = []byte("new")
				if _, err := jetstream.PublishMsg(unrelated); err != nil {
					recreateErr = err
					return
				}
			}
		})
		if recreateErr != nil {
			return nil, recreateErr
		}
		return realPublish(message, options...)
	}
	if err := sink.Record(context.Background(), record); err == nil {
		t.Fatal("conditional publish accepted a stale stream epoch")
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != 7 {
		t.Fatalf("stale conditional publish changed recreated stream: state=%+v err=%v", info, err)
	}
	sink.publishMessage = nil
	restarted, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		err = restarted.Record(context.Background(), record)
		if err == nil {
			break
		}
		if !errors.Is(err, errIsolationEvidenceScanPending) {
			t.Fatalf("recreated stream retry failed closed permanently: %v", err)
		}
	}
	if err != nil {
		t.Fatalf("recreated stream retry did not complete: %v", err)
	}
	info, err = jetstream.StreamInfo(config.IsolationStream)
	if err != nil || info.State.Msgs != 8 {
		t.Fatalf("recreated stream final state=%+v err=%v", info, err)
	}
}

func TestOBSUsageARound9RealPostBindConsumerDriftFailsClosed(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	if err := consumer.unbindSubscription(); err != nil {
		t.Fatal(err)
	}
	delayed := &round8DelayedPullJetStream{
		JetStreamContext: consumer.jetstream, entered: make(chan struct{}), release: make(chan struct{}),
	}
	consumer.jetstream = delayed
	bindDone := make(chan error, 1)
	go func() { bindDone <- consumer.bindSubscription() }()
	select {
	case <-delayed.entered:
	case <-time.After(3 * time.Second):
		close(delayed.release)
		t.Fatal("real post-bind drift did not reach PullSubscribe barrier")
	}
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable)
	if err != nil {
		close(delayed.release)
		t.Fatal(err)
	}
	drifted := info.Config
	drifted.AckWait += time.Second
	if _, err := jetstream.UpdateConsumer(config.Stream, &drifted); err != nil {
		close(delayed.release)
		t.Fatal(err)
	}
	close(delayed.release)
	if err := <-bindDone; err == nil {
		t.Fatal("production bind accepted real broker consumer drift")
	}
	consumer.mu.Lock()
	installed := consumer.subscription
	consumer.mu.Unlock()
	delayed.mu.Lock()
	local := delayed.subscription
	delayed.mu.Unlock()
	if installed != nil || local == nil || local.IsValid() {
		t.Fatalf("real drift leaked subscription: installed=%v local=%v valid=%t", installed != nil, local != nil, local != nil && local.IsValid())
	}
	if _, err := jetstream.UpdateConsumer(config.Stream, expectedConsumer(config)); err != nil {
		t.Fatal(err)
	}
	consumer.jetstream = jetstream
	if err := consumer.bindSubscription(); err != nil {
		t.Fatalf("exact broker consumer config false-rejected after drift repair: %v", err)
	}
}

type round10ConfirmBarrierKeyValue struct {
	nats.KeyValue
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (store *round10ConfirmBarrierKeyValue) Update(key string, value []byte, revision uint64) (uint64, error) {
	var state parkedDeliveryState
	if strings.HasPrefix(key, "parked.") && json.Unmarshal(value, &state) == nil &&
		state.Phase == parkedPhaseEvidenceConfirmed {
		store.once.Do(func() { close(store.entered) })
		<-store.release
	}
	return store.KeyValue.Update(key, value, revision)
}

type round10PauseAfterRecordTerminalSink struct {
	*NATSIsolationSink
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (sink *round10PauseAfterRecordTerminalSink) RecordTerminal(
	ctx context.Context,
	delivery IngestDelivery,
	record IsolationRecord,
) error {
	if err := sink.NATSIsolationSink.RecordTerminal(ctx, delivery, record); err != nil {
		return err
	}
	sink.once.Do(func() { close(sink.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-sink.release:
		return nil
	}
}

type round10ProcessResult struct {
	result IngestBatchResult
	err    error
}

func TestOBSUsageARound10TerminalConfirmationIsRevalidatedAtTermBoundary(t *testing.T) {
	for _, window := range []string{"confirm-cas", "confirm-to-term"} {
		t.Run(window, func(t *testing.T) {
			connection, jetstream := connectRound7JetStream(t)
			config := obsUsageAJetStreamConfig()
			config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
				t.Fatal(err)
			}
			consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round10-"+window)
			defer consumer.Close()
			var isolation IsolationSink = sink
			var entered chan struct{}
			var release chan struct{}
			if window == "confirm-cas" {
				barrier := &round10ConfirmBarrierKeyValue{
					KeyValue: consumer.stateStore, entered: make(chan struct{}), release: make(chan struct{}),
				}
				consumer.stateStore = barrier
				sink.stateStore = barrier
				entered, release = barrier.entered, barrier.release
			} else {
				paused := &round10PauseAfterRecordTerminalSink{
					NATSIsolationSink: sink, entered: make(chan struct{}), release: make(chan struct{}),
				}
				isolation = paused
				entered, release = paused.entered, paused.release
			}
			processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, isolation, IngestProcessorConfig{
				OperationTimeout: 10 * time.Second,
			})
			done := make(chan round10ProcessResult, 1)
			go func() {
				result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
				done <- round10ProcessResult{result: result, err: err}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("terminal confirmation did not reach deterministic barrier")
			}
			if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
				close(release)
				t.Fatal(err)
			}
			if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
				close(release)
				t.Fatal(err)
			}
			close(release)
			outcome := <-done
			if outcome.err == nil || outcome.result.Terminated != 0 || outcome.result.Naked != 1 {
				t.Fatalf("stale confirmation terminated source: result=%+v err=%v", outcome.result, outcome.err)
			}
			if _, err := jetstream.GetMsg(config.Stream, delivery.streamSequence); err != nil {
				t.Fatalf("stale confirmation removed source message: %v", err)
			}
			entry, err := consumer.stateStore.Get(parkedStateKey(delivery.streamSequence))
			if err != nil {
				t.Fatalf("stale confirmation removed durable marker: %v", err)
			}
			state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
			if err != nil {
				t.Fatal(err)
			}
			if window == "confirm-cas" && state.EvidenceConfirmed {
				t.Fatalf("confirm-CAS epoch change remained terminally confirmed: %+v", state)
			}
		})
	}
}

type round10FlakyRecoveryKeyValue struct {
	nats.KeyValue
	mu              sync.Mutex
	getFailures     int
	getAttempts     int
	confirmFailures []error
	confirmAttempts int
}

func (store *round10FlakyRecoveryKeyValue) Get(key string) (nats.KeyValueEntry, error) {
	store.mu.Lock()
	if strings.HasPrefix(key, "parked.") {
		store.getAttempts++
		if store.getFailures > 0 {
			store.getFailures--
			store.mu.Unlock()
			return nil, context.DeadlineExceeded
		}
	}
	store.mu.Unlock()
	return store.KeyValue.Get(key)
}

func (store *round10FlakyRecoveryKeyValue) Update(key string, value []byte, revision uint64) (uint64, error) {
	var state parkedDeliveryState
	confirmed := strings.HasPrefix(key, "parked.") && json.Unmarshal(value, &state) == nil &&
		state.Phase == parkedPhaseEvidenceConfirmed
	store.mu.Lock()
	if confirmed {
		store.confirmAttempts++
		if len(store.confirmFailures) > 0 {
			err := store.confirmFailures[0]
			store.confirmFailures = store.confirmFailures[1:]
			store.mu.Unlock()
			return 0, err
		}
	}
	store.mu.Unlock()
	return store.KeyValue.Update(key, value, revision)
}

func (store *round10FlakyRecoveryKeyValue) attempts() (int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.getAttempts, store.confirmAttempts
}

func TestOBSUsageARound10RecoveryRetriesReloadConfirmCASEpochAndResumesAfterOpen(t *testing.T) {
	t.Run("retryable-boundaries", func(t *testing.T) {
		connection, jetstream := connectRound7JetStream(t)
		config := obsUsageAJetStreamConfig()
		config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
		config.StreamMaxMessages = 1000
		defer cleanupOBSUsageAJetStream(t, jetstream, config)
		if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 160; index++ {
			message := nats.NewMsg(IsolationSubject)
			message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round10-retry-%03d", index))
			message.Data = []byte("unrelated")
			if _, err := jetstream.PublishMsg(message); err != nil {
				t.Fatal(err)
			}
		}
		consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round10-retryable")
		defer consumer.Close()
		intent, err := sink.prepareTerminalEvidence(
			context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
		)
		if err != nil {
			t.Fatal(err)
		}
		flaky := &round10FlakyRecoveryKeyValue{
			KeyValue: consumer.stateStore, getFailures: 1,
			confirmFailures: []error{nats.ErrKeyExists, context.DeadlineExceeded},
		}
		consumer.stateStore = flaky
		sink.stateStore = flaky
		realPublish := sink.jetstream.PublishMsg
		var recreate sync.Once
		sink.publishMessage = func(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
			ack, err := realPublish(message, options...)
			if err == nil {
				recreate.Do(func() {
					if deleteErr := jetstream.DeleteStream(config.IsolationStream); deleteErr != nil {
						err = deleteErr
						return
					}
					_, err = jetstream.AddStream(expectedIsolationStream(config))
				})
			}
			return ack, err
		}
		sink.startTerminalEvidenceRecovery(delivery, intent)
		state := round10WaitEvidenceConfirmed(t, flaky.KeyValue, delivery.streamSequence, 8*time.Second)
		gets, confirms := flaky.attempts()
		if gets < 2 || confirms < 3 {
			t.Fatalf("retryable recovery did not cross every boundary: gets=%d confirms=%d state=%+v", gets, confirms, state)
		}
		info, err := jetstream.StreamInfo(config.IsolationStream)
		if err != nil || state.EvidenceStreamCreated != info.Created.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("post-publish epoch recovery state=%+v stream=%+v err=%v", state, info, err)
		}
	})

	t.Run("close-open", func(t *testing.T) {
		connection, jetstream := connectRound7JetStream(t)
		config := obsUsageAJetStreamConfig()
		config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
		defer cleanupOBSUsageAJetStream(t, jetstream, config)
		if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
			t.Fatal(err)
		}
		consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round10-close-open")
		intent, err := sink.prepareTerminalEvidence(
			context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
		)
		if err != nil {
			t.Fatal(err)
		}
		realStore := consumer.stateStore
		flaky := &round10FlakyRecoveryKeyValue{KeyValue: realStore, getFailures: 100}
		consumer.stateStore = flaky
		sink.stateStore = flaky
		sink.startTerminalEvidenceRecovery(delivery, intent)
		round10WaitRecoveryAttempts(t, flaky, 2, 3*time.Second)
		consumer.stateStore = realStore
		sink.stateStore = realStore
		if err := delivery.Nak(context.Background(), 0); err != nil {
			t.Fatal(err)
		}
		if err := consumer.Close(); err != nil {
			t.Fatal(err)
		}
		round10WaitRecoveringEmpty(t, sink, 2*time.Second)

		restarted, err := NewNATSIngestConsumer(connection, config)
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close()
		replayed := round6WaitDelivery(t, restarted, 5*time.Second)
		restartedSink, err := NewNATSIsolationSink(connection, config)
		if err != nil {
			t.Fatal(err)
		}
		processor := mustProcessor(t, time.Now().UTC(), &fakeIngestWriter{}, restartedSink, IngestProcessorConfig{
			OperationTimeout: 10 * time.Second,
		})
		result, processErr := processor.Process(context.Background(), []IngestDelivery{replayed})
		if processErr != nil || result.Terminated != 1 || result.Naked != 0 {
			t.Fatalf("reopened recovery result=%+v err=%v", result, processErr)
		}
	})
}

type round10BlockingGetJetStream struct {
	nats.JetStreamContext
	mu      sync.Mutex
	current int
	maximum int
	entered chan struct{}
	release chan struct{}
}

func (jetstream *round10BlockingGetJetStream) GetMsg(
	stream string,
	sequence uint64,
	options ...nats.JSOpt,
) (*nats.RawStreamMsg, error) {
	jetstream.mu.Lock()
	jetstream.current++
	jetstream.maximum = max(jetstream.maximum, jetstream.current)
	jetstream.mu.Unlock()
	select {
	case jetstream.entered <- struct{}{}:
	default:
	}
	<-jetstream.release
	defer func() {
		jetstream.mu.Lock()
		jetstream.current--
		jetstream.mu.Unlock()
	}()
	return jetstream.JetStreamContext.GetMsg(stream, sequence, options...)
}

func (jetstream *round10BlockingGetJetStream) maxConcurrent() int {
	jetstream.mu.Lock()
	defer jetstream.mu.Unlock()
	return jetstream.maximum
}

func TestOBSUsageARound10RecoverySchedulerIsBoundedCoalescedAndFair(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.MaxAckPending = 16
	config.StreamMaxMessages = 1000
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 192; index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round10-fair-%03d", index))
		message.Data = []byte("unrelated")
		if _, err := jetstream.PublishMsg(message); err != nil {
			t.Fatal(err)
		}
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
	const deliveriesCount = 12
	for index := 0; index < deliveriesCount; index++ {
		message := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round10-fair-terminal-%02d", index))
		setIntegrationAuthority(message, testConfigVersionID)
		message.Data = []byte("{")
		if _, err := jetstream.PublishMsg(message); err != nil {
			t.Fatal(err)
		}
	}
	deliveries := make([]*natsIngestDelivery, 0, deliveriesCount)
	for len(deliveries) < deliveriesCount {
		batch, fetchErr := consumer.Fetch(context.Background())
		if fetchErr != nil {
			t.Fatal(fetchErr)
		}
		for _, item := range batch {
			deliveries = append(deliveries, item.(*natsIngestDelivery))
		}
	}
	intents := make([]isolationPublishIntent, 0, deliveriesCount)
	for _, delivery := range deliveries {
		intent, err := sink.prepareTerminalEvidence(
			context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
		)
		if err != nil {
			t.Fatal(err)
		}
		intents = append(intents, intent)
	}
	blocker := &round10BlockingGetJetStream{
		JetStreamContext: sink.jetstream, entered: make(chan struct{}, deliveriesCount*2), release: make(chan struct{}),
	}
	sink.jetstream = blocker
	for index, intent := range intents {
		sink.startTerminalEvidenceRecovery(deliveries[index], intent)
		sink.startTerminalEvidenceRecovery(deliveries[index], intent)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(blocker.entered) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	maximum := blocker.maxConcurrent()
	close(blocker.release)
	if maximum > 2 || maximum == 0 {
		t.Fatalf("recovery scheduler concurrency=%d want=1..2", maximum)
	}
	for _, delivery := range deliveries {
		round12WaitParkedMarkerSettled(t, consumer.stateStore, delivery.streamSequence, 8*time.Second)
	}
	round10WaitRecoveringEmpty(t, sink, 2*time.Second)
}

type round11StreamInfoProbe struct {
	nats.JetStreamContext
	mu             sync.Mutex
	streamNotFound int
}

func (probe *round11StreamInfoProbe) StreamInfo(
	stream string,
	options ...nats.JSOpt,
) (*nats.StreamInfo, error) {
	info, err := probe.JetStreamContext.StreamInfo(stream, options...)
	if errors.Is(err, nats.ErrStreamNotFound) {
		probe.mu.Lock()
		probe.streamNotFound++
		probe.mu.Unlock()
	}
	return info, err
}

func (probe *round11StreamInfoProbe) missingAttempts() int {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.streamNotFound
}

func TestOBSUsageARound11StreamDeleteAddGapRetriesAcrossWorkerTurns(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round11-stream-gap")
	defer consumer.Close()
	intent, err := sink.prepareTerminalEvidence(
		context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
	)
	if err != nil {
		t.Fatal(err)
	}
	probe := &round11StreamInfoProbe{JetStreamContext: sink.jetstream}
	sink.jetstream = probe
	if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
		t.Fatal(err)
	}
	sink.startTerminalEvidenceRecovery(delivery, intent)
	deadline := time.Now().Add(3 * time.Second)
	for probe.missingAttempts() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	attempts := probe.missingAttempts()
	if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
		t.Fatal(err)
	}
	if attempts < 3 {
		t.Fatalf("stream-not-found recovery attempts=%d want>=3 before recreate", attempts)
	}
	state := round10WaitEvidenceConfirmed(t, consumer.stateStore, delivery.streamSequence, 5*time.Second)
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || state.EvidenceStreamCreated != info.Created.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("recreated stream recovery state=%+v info=%+v err=%v", state, info, err)
	}
}

type round11RetryMatrixKeyValue struct {
	nats.KeyValue
	mu              sync.Mutex
	getFailures     []error
	confirmFailures []error
	getAttempts     int
	confirmAttempts int
}

func (store *round11RetryMatrixKeyValue) Get(key string) (nats.KeyValueEntry, error) {
	store.mu.Lock()
	if strings.HasPrefix(key, "parked.") {
		store.getAttempts++
		if len(store.getFailures) > 0 {
			err := store.getFailures[0]
			store.getFailures = store.getFailures[1:]
			store.mu.Unlock()
			return nil, err
		}
	}
	store.mu.Unlock()
	return store.KeyValue.Get(key)
}

func (store *round11RetryMatrixKeyValue) Update(
	key string,
	value []byte,
	revision uint64,
) (uint64, error) {
	var state parkedDeliveryState
	confirmed := strings.HasPrefix(key, "parked.") && json.Unmarshal(value, &state) == nil &&
		state.Phase == parkedPhaseEvidenceConfirmed
	store.mu.Lock()
	if confirmed {
		store.confirmAttempts++
		if len(store.confirmFailures) > 0 {
			err := store.confirmFailures[0]
			store.confirmFailures = store.confirmFailures[1:]
			store.mu.Unlock()
			return 0, err
		}
	}
	store.mu.Unlock()
	return store.KeyValue.Update(key, value, revision)
}

func (store *round11RetryMatrixKeyValue) attempts() (int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.getAttempts, store.confirmAttempts
}

func TestOBSUsageARound11RecoveryRetryMatrixAndPermanentFailure(t *testing.T) {
	t.Run("retryable", func(t *testing.T) {
		connection, jetstream := connectRound7JetStream(t)
		config := obsUsageAJetStreamConfig()
		config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
		defer cleanupOBSUsageAJetStream(t, jetstream, config)
		if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
			t.Fatal(err)
		}
		consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round11-retry-matrix")
		defer consumer.Close()
		intent, err := sink.prepareTerminalEvidence(
			context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
		)
		if err != nil {
			t.Fatal(err)
		}
		store := &round11RetryMatrixKeyValue{
			KeyValue: consumer.stateStore,
			getFailures: []error{
				context.DeadlineExceeded,
				nats.ErrTimeout,
				nats.ErrNoResponders,
				nats.ErrDisconnected,
				nats.ErrConnectionClosed,
				nats.ErrKeyExists,
			},
			confirmFailures: []error{nats.ErrKeyExists},
		}
		consumer.stateStore = store
		sink.stateStore = store
		realPublish := sink.jetstream.PublishMsg
		var recreated bool
		sink.publishMessage = func(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
			ack, publishErr := realPublish(message, options...)
			if publishErr == nil && !recreated {
				recreated = true
				if deleteErr := jetstream.DeleteStream(config.IsolationStream); deleteErr != nil {
					return ack, deleteErr
				}
				if _, addErr := jetstream.AddStream(expectedIsolationStream(config)); addErr != nil {
					return ack, addErr
				}
			}
			return ack, publishErr
		}
		sink.startTerminalEvidenceRecovery(delivery, intent)
		state := round10WaitEvidenceConfirmed(t, store.KeyValue, delivery.streamSequence, 8*time.Second)
		gets, confirms := store.attempts()
		if gets < 7 || confirms < 2 || !recreated {
			t.Fatalf("retry matrix incomplete: gets=%d confirms=%d recreated=%t state=%+v", gets, confirms, recreated, state)
		}
	})

	t.Run("permanent-observable", func(t *testing.T) {
		connection, jetstream := connectRound7JetStream(t)
		config := obsUsageAJetStreamConfig()
		config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
		defer cleanupOBSUsageAJetStream(t, jetstream, config)
		if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
			t.Fatal(err)
		}
		consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round11-permanent")
		defer consumer.Close()
		intent, err := sink.prepareTerminalEvidence(
			context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
		)
		if err != nil {
			t.Fatal(err)
		}
		store := &round11RetryMatrixKeyValue{KeyValue: consumer.stateStore, getFailures: []error{ErrInvalidInput}}
		consumer.stateStore = store
		sink.stateStore = store
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		defer slog.SetDefault(previous)
		sink.startTerminalEvidenceRecovery(delivery, intent)
		round10WaitRecoveringEmpty(t, sink, 2*time.Second)
		gets, _ := store.attempts()
		if gets != 1 || !strings.Contains(logs.String(), "analytics terminal evidence recovery stopped") {
			t.Fatalf("permanent recovery attempts=%d logs=%q", gets, logs.String())
		}
	})
}

type round11BlockingScanJetStream struct {
	nats.JetStreamContext
	lifecycle context.Context
	entered   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (jetstream *round11BlockingScanJetStream) GetMsg(
	string,
	uint64,
	...nats.JSOpt,
) (*nats.RawStreamMsg, error) {
	jetstream.once.Do(func() { close(jetstream.entered) })
	<-jetstream.lifecycle.Done()
	select {
	case <-jetstream.cancelled:
	default:
		close(jetstream.cancelled)
	}
	<-jetstream.release
	return nil, jetstream.lifecycle.Err()
}

func TestOBSUsageARound11CloseOwnsBackoffScanPublishAndImmediateReopen(t *testing.T) {
	t.Run("backoff", func(t *testing.T) {
		connection, jetstream := connectRound7JetStream(t)
		config := obsUsageAJetStreamConfig()
		config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
		defer cleanupOBSUsageAJetStream(t, jetstream, config)
		if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
			t.Fatal(err)
		}
		consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round11-close-backoff")
		intent, err := sink.prepareTerminalEvidence(
			context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
		)
		if err != nil {
			t.Fatal(err)
		}
		store := &round11RetryMatrixKeyValue{KeyValue: consumer.stateStore, getFailures: make([]error, 8)}
		for index := range store.getFailures {
			store.getFailures[index] = nats.ErrTimeout
		}
		consumer.stateStore = store
		sink.stateStore = store
		sink.startTerminalEvidenceRecovery(delivery, intent)
		deadline := time.Now().Add(3 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			sink.recoveryMu.Lock()
			for _, task := range sink.recoveryQueue {
				ready = ready || task.readyAt.After(time.Now().Add(100*time.Millisecond))
			}
			sink.recoveryMu.Unlock()
			if ready {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !ready {
			t.Fatal("recovery did not enter bounded backoff")
		}
		if err := consumer.Close(); err != nil {
			t.Fatal(err)
		}
		remaining, queued, workers := round11RecoveryCounts(sink)
		if remaining != 0 || queued != 0 || workers != 0 {
			sink.recoveryMu.Lock()
			for range isolationEvidenceRecoveryWorkers {
				sink.wakeTerminalEvidenceRecoveryLocked()
			}
			sink.recoveryMu.Unlock()
			t.Fatalf("Close returned before backoff shutdown: remaining=%d queued=%d workers=%d", remaining, queued, workers)
		}
		restarted, err := NewNATSIngestConsumer(connection, config)
		if err != nil {
			t.Fatalf("immediate reopen after joined Close: %v", err)
		}
		if err := restarted.Close(); err != nil {
			t.Fatal(err)
		}
	})

	for _, boundary := range []string{"scan", "publish"} {
		t.Run(boundary, func(t *testing.T) {
			connection, jetstream := connectRound7JetStream(t)
			config := obsUsageAJetStreamConfig()
			config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
			defer cleanupOBSUsageAJetStream(t, jetstream, config)
			if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
				t.Fatal(err)
			}
			if boundary == "scan" {
				message := nats.NewMsg(IsolationSubject)
				message.Header.Set(nats.MsgIdHdr, "round11-close-scan-unrelated")
				message.Data = []byte("unrelated")
				if _, err := jetstream.PublishMsg(message); err != nil {
					t.Fatal(err)
				}
			}
			consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round11-close-"+boundary)
			intent, err := sink.prepareTerminalEvidence(
				context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
			)
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			cancelled := make(chan struct{})
			release := make(chan struct{})
			if boundary == "scan" {
				sink.jetstream = &round11BlockingScanJetStream{
					JetStreamContext: sink.jetstream, lifecycle: consumer.lifecycleCtx,
					entered: entered, cancelled: cancelled, release: release,
				}
			} else {
				sink.publishMessage = func(*nats.Msg, ...nats.PubOpt) (*nats.PubAck, error) {
					close(entered)
					<-consumer.lifecycleCtx.Done()
					close(cancelled)
					<-release
					return nil, consumer.lifecycleCtx.Err()
				}
			}
			sink.startTerminalEvidenceRecovery(delivery, intent)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatalf("recovery did not reach %s boundary", boundary)
			}
			closeDone := make(chan error, 1)
			go func() { closeDone <- consumer.Close() }()
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				close(release)
				t.Fatalf("Close did not cancel %s boundary", boundary)
			}
			returnedEarly := false
			select {
			case err := <-closeDone:
				returnedEarly = true
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			if !returnedEarly {
				select {
				case err := <-closeDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatalf("Close did not join %s recovery", boundary)
				}
			}
			remaining, queued, workers := round11RecoveryCounts(sink)
			if returnedEarly || remaining != 0 || queued != 0 || workers != 0 {
				t.Fatalf("Close returned before %s shutdown: early=%t remaining=%d queued=%d workers=%d",
					boundary, returnedEarly, remaining, queued, workers)
			}
			restarted, err := NewNATSIngestConsumer(connection, config)
			if err != nil {
				t.Fatalf("immediate reopen after %s Close: %v", boundary, err)
			}
			if oldRemaining, oldQueued, oldWorkers := round11RecoveryCounts(sink); oldRemaining != 0 ||
				oldQueued != 0 || oldWorkers != 0 {
				t.Fatalf("immediate reopen overlapped old scheduler: %d/%d/%d", oldRemaining, oldQueued, oldWorkers)
			}
			if err := restarted.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func round11RecoveryCounts(sink *NATSIsolationSink) (int, int, int) {
	sink.recoveryMu.Lock()
	defer sink.recoveryMu.Unlock()
	return len(sink.recovering), len(sink.recoveryQueue), sink.recoveryWorkers
}

type round11ReadCountingJetStream struct {
	nats.JetStreamContext
	mu    sync.Mutex
	reads int
}

func (jetstream *round11ReadCountingJetStream) GetMsg(
	stream string,
	sequence uint64,
	options ...nats.JSOpt,
) (*nats.RawStreamMsg, error) {
	jetstream.mu.Lock()
	jetstream.reads++
	jetstream.mu.Unlock()
	return jetstream.JetStreamContext.GetMsg(stream, sequence, options...)
}

func (jetstream *round11ReadCountingJetStream) takeReads() int {
	jetstream.mu.Lock()
	defer jetstream.mu.Unlock()
	reads := jetstream.reads
	jetstream.reads = 0
	return reads
}

func TestOBSUsageARound11UnknownPublishYieldsAtTotalReadBudget(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.StreamMaxMessages = 1000
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < int(isolationEvidenceScanBatch); index++ {
		message := nats.NewMsg(IsolationSubject)
		message.Header.Set(nats.MsgIdHdr, fmt.Sprintf("round11-budget-%02d", index))
		message.Data = []byte("unrelated")
		if _, err := jetstream.PublishMsg(message); err != nil {
			t.Fatal(err)
		}
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round11-budget-terminal")
	defer consumer.Close()
	intent, err := sink.prepareTerminalEvidence(
		context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
	)
	if err != nil {
		t.Fatal(err)
	}
	counter := &round11ReadCountingJetStream{JetStreamContext: sink.jetstream}
	sink.jetstream = counter
	realPublish := counter.JetStreamContext.PublishMsg
	sink.publishMessage = func(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
		if _, publishErr := realPublish(message, options...); publishErr != nil {
			return nil, publishErr
		}
		return nil, context.DeadlineExceeded
	}
	_, firstErr := sink.publishEvidenceIntent(context.Background(), intent)
	firstReads := counter.takeReads()
	if firstReads > int(isolationEvidenceScanBatch) || !errors.Is(firstErr, errIsolationEvidenceScanPending) {
		t.Fatalf("unknown publish turn reads=%d limit=%d err=%v", firstReads, isolationEvidenceScanBatch, firstErr)
	}
	current, err := sink.reloadTerminalIsolationIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := sink.publishEvidenceIntent(context.Background(), current)
	secondReads := counter.takeReads()
	if err != nil || sequence == 0 || secondReads > int(isolationEvidenceScanBatch) {
		t.Fatalf("yielded reconciliation sequence=%d reads=%d err=%v", sequence, secondReads, err)
	}
}

type round11PostTermBarrierJetStream struct {
	nats.JetStreamContext
	stream  string
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (jetstream *round11PostTermBarrierJetStream) StreamInfo(
	stream string,
	options ...nats.JSOpt,
) (*nats.StreamInfo, error) {
	if stream == jetstream.stream {
		jetstream.mu.Lock()
		jetstream.calls++
		call := jetstream.calls
		jetstream.mu.Unlock()
		if call == 3 {
			jetstream.once.Do(func() { close(jetstream.entered) })
			<-jetstream.release
		}
	}
	return jetstream.JetStreamContext.StreamInfo(stream, options...)
}

func TestOBSUsageARound11PostTermEpochChangeRetainsMarkerAndDoesNotRepeatTerm(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round11-post-term")
	defer consumer.Close()
	intent, _ := round7ConfirmEvidence(t, sink, delivery)
	var termMu sync.Mutex
	termCount := 0
	observer, err := connection.Subscribe(delivery.message.Reply, func(message *nats.Msg) {
		if strings.Contains(string(message.Data), "+TERM") {
			termMu.Lock()
			termCount++
			termMu.Unlock()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Unsubscribe()
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	barrier := &round11PostTermBarrierJetStream{
		JetStreamContext: consumer.jetstream, stream: config.IsolationStream,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	consumer.jetstream = barrier
	done := make(chan error, 1)
	go func() { done <- delivery.Term(context.Background()) }()
	select {
	case <-barrier.entered:
	case <-time.After(3 * time.Second):
		close(barrier.release)
		t.Fatal("Term did not reach post-settlement evidence barrier")
	}
	if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
		close(barrier.release)
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
		close(barrier.release)
		t.Fatal(err)
	}
	close(barrier.release)
	if err := <-done; err == nil {
		t.Fatal("post-Term epoch recreation reported false success")
	}
	if _, err := consumer.stateStore.Get(parkedStateKey(delivery.streamSequence)); err != nil {
		t.Fatalf("post-Term epoch recreation removed parked marker: %v", err)
	}
	sink.startTerminalEvidenceRecovery(delivery, intent)
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil {
		t.Fatal(err)
	}
	round11WaitEvidenceEpoch(t, consumer.stateStore, delivery.streamSequence, info.Created, 5*time.Second)
	round12WaitParkedMarkerSettled(t, consumer.stateStore, delivery.streamSequence, 5*time.Second)
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		termMu.Lock()
		count := termCount
		termMu.Unlock()
		if count >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	termMu.Lock()
	count := termCount
	termMu.Unlock()
	if count != 1 {
		t.Fatalf("source Term action count=%d want=1 across post-Term recovery", count)
	}
}

func TestOBSUsageARound12SameEpochEvidenceHoleRecoversAndSettlesIndependently(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	// 证据 MsgId 绑定在不可变加密意图里（Round14），洞只能在去重窗口过期后补；同 Round7 洞用例取短窗口。
	config.DuplicateWindow = 500 * time.Millisecond
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round12-same-epoch-hole")
	defer consumer.Close()
	intent, sequence := round7ConfirmEvidence(t, sink, delivery)
	if err := jetstream.DeleteMsg(config.IsolationStream, sequence); err != nil {
		t.Fatal(err)
	}
	// 同 MsgId 重发在去重窗口内命中已删序号（PubAck duplicate 指向被删消息），
	// 恢复只能等窗口过期；期间必须退避，不能按 1ms 空转。
	realPublish := sink.jetstream.PublishMsg
	var publishMu sync.Mutex
	publishes := 0
	sink.publishMessage = func(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
		publishMu.Lock()
		publishes++
		publishMu.Unlock()
		return realPublish(message, options...)
	}
	sink.startTerminalEvidenceRecovery(delivery, intent)
	round12WaitParkedMarkerSettled(t, consumer.stateStore, delivery.streamSequence, 5*time.Second)
	publishMu.Lock()
	attempts := publishes
	publishMu.Unlock()
	if attempts > 20 {
		t.Fatalf("dedupe-hidden evidence hole retried publish %d times within one %s window, want backoff", attempts, config.DuplicateWindow)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("same-epoch recovery evidence messages=%d want=1", info.State.Msgs)
	}
	if _, err := jetstream.GetMsg(config.Stream, delivery.streamSequence); !errors.Is(err, nats.ErrMsgNotFound) {
		t.Fatalf("terminal source still exists after independent recovery: %v", err)
	}
}

type round12SettledRecreateStore struct {
	nats.KeyValue
	jetstream    nats.JetStreamContext
	config       JetStreamConfig
	mu           sync.Mutex
	recreated    bool
	unsafeDelete int
}

func (store *round12SettledRecreateStore) Update(key string, value []byte, revision uint64) (uint64, error) {
	next, err := store.KeyValue.Update(key, value, revision)
	if err != nil || !strings.HasPrefix(key, "parked.") {
		return next, err
	}
	state, decodeErr := decodeParkedDeliveryState(value, mustParseRound12ParkedSequence(key))
	if decodeErr != nil || state.Phase != parkedPhaseSettled {
		return next, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.recreated {
		return next, err
	}
	store.recreated = true
	if deleteErr := store.jetstream.DeleteStream(store.config.IsolationStream); deleteErr != nil {
		return next, deleteErr
	}
	_, addErr := store.jetstream.AddStream(expectedIsolationStream(store.config))
	return next, addErr
}

func (store *round12SettledRecreateStore) Delete(key string, options ...nats.DeleteOpt) error {
	if strings.HasPrefix(key, "parked.") {
		info, err := store.jetstream.StreamInfo(store.config.IsolationStream)
		store.mu.Lock()
		if err == nil && info.State.Msgs == 0 {
			store.unsafeDelete++
		}
		store.mu.Unlock()
	}
	return store.KeyValue.Delete(key, options...)
}

func (store *round12SettledRecreateStore) counts() (bool, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.recreated, store.unsafeDelete
}

func TestOBSUsageARound12SettledDeleteRevalidatesEvidenceEpoch(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round12-settled-recreate")
	defer consumer.Close()
	round7ConfirmEvidence(t, sink, delivery)
	store := &round12SettledRecreateStore{KeyValue: consumer.stateStore, jetstream: jetstream, config: config}
	consumer.stateStore = store
	sink.stateStore = store
	if err := delivery.Term(context.Background()); err == nil {
		t.Fatal("settlement succeeded after isolation epoch changed before marker deletion")
	}
	// marker 在换代前已写为 settled，须等恢复把证据补进新 epoch 后再判收敛。
	recreatedInfo, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil {
		t.Fatal(err)
	}
	round11WaitEvidenceEpoch(t, store.KeyValue, delivery.streamSequence, recreatedInfo.Created, 5*time.Second)
	round12WaitParkedMarkerSettled(t, store.KeyValue, delivery.streamSequence, 5*time.Second)
	recreated, unsafeDeletes := store.counts()
	if !recreated || unsafeDeletes != 0 {
		t.Fatalf("settled recreation=%t unsafe marker deletes=%d", recreated, unsafeDeletes)
	}
	info, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("settled recovery evidence messages=%d want=1", info.State.Msgs)
	}
}

type round13AfterStreamInfoJetStream struct {
	nats.JetStreamContext
	stream     string
	targetCall int
	mu         sync.Mutex
	calls      int
	entered    chan struct{}
	release    chan struct{}
	once       sync.Once
}

func (jetstream *round13AfterStreamInfoJetStream) StreamInfo(
	stream string,
	options ...nats.JSOpt,
) (*nats.StreamInfo, error) {
	info, err := jetstream.JetStreamContext.StreamInfo(stream, options...)
	if stream != jetstream.stream || err != nil {
		return info, err
	}
	jetstream.mu.Lock()
	jetstream.calls++
	call := jetstream.calls
	jetstream.mu.Unlock()
	if call == jetstream.targetCall {
		jetstream.once.Do(func() { close(jetstream.entered) })
		<-jetstream.release
	}
	return info, nil
}

func TestOBSUsageARound13LiveFinalEvidenceCheckCannotDeleteRecoveryProof(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round13-live-delete-window")
	defer consumer.Close()
	intent, _ := round7ConfirmEvidence(t, sink, delivery)
	blobKey := isolationEvidenceBlobKey(consumer.streamCreated, delivery.streamSequence)
	blobBefore, err := sink.evidenceStore.Get(blobKey)
	if err != nil {
		t.Fatal(err)
	}
	blobBytes := append([]byte(nil), blobBefore.Value()...)
	barrier := &round13AfterStreamInfoJetStream{
		JetStreamContext: consumer.jetstream, stream: config.IsolationStream, targetCall: 6,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	consumer.jetstream = barrier
	done := make(chan error, 1)
	go func() { done <- delivery.Term(context.Background()) }()
	select {
	case <-barrier.entered:
	case <-time.After(3 * time.Second):
		close(barrier.release)
		t.Fatal("live settlement did not reach the post-validation deletion window")
	}
	if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
		close(barrier.release)
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
		close(barrier.release)
		t.Fatal(err)
	}
	close(barrier.release)
	if err := <-done; err != nil {
		t.Fatalf("live settlement failed after its final evidence check: %v", err)
	}
	entry, err := consumer.stateStore.Get(parkedStateKey(delivery.streamSequence))
	if err != nil {
		t.Fatalf("live settlement deleted its only durable recovery proof: %v", err)
	}
	state, err := decodeParkedDeliveryState(entry.Value(), delivery.streamSequence)
	if err != nil || state.Phase != parkedPhaseSettled || !state.TermSent {
		t.Fatalf("retained live settlement state=%+v err=%v", state, err)
	}
	round14WaitRetainedRecovery(t, consumer, 15*time.Second)
	stored, err := jetstream.GetMsg(config.IsolationStream, 1)
	if err != nil || stored.Subject != intent.Subject || stored.Header.Get(nats.MsgIdHdr) != intent.MessageID ||
		!bytes.Equal(stored.Data, intent.Payload) {
		t.Fatalf("live retained-proof exact evidence=%+v err=%v", stored, err)
	}
	blobAfter, err := sink.evidenceStore.Get(blobKey)
	if err != nil || !bytes.Equal(blobAfter.Value(), blobBytes) {
		t.Fatalf("live retained-proof immutable blob changed: err=%v", err)
	}
}

type round13AfterGetMsgJetStream struct {
	nats.JetStreamContext
	stream  string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (jetstream *round13AfterGetMsgJetStream) GetMsg(
	stream string,
	sequence uint64,
	options ...nats.JSOpt,
) (*nats.RawStreamMsg, error) {
	message, err := jetstream.JetStreamContext.GetMsg(stream, sequence, options...)
	if stream == jetstream.stream && err == nil {
		jetstream.once.Do(func() {
			close(jetstream.entered)
			<-jetstream.release
		})
	}
	return message, err
}

func TestOBSUsageARound13RestartFinalEvidenceCheckCannotDeleteRecoveryProof(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round13-restart-delete-window")
	intent, _ := round7ConfirmEvidence(t, sink, delivery)
	blobKey := isolationEvidenceBlobKey(consumer.streamCreated, delivery.streamSequence)
	blobBefore, err := sink.evidenceStore.Get(blobKey)
	if err != nil {
		t.Fatal(err)
	}
	blobBytes := append([]byte(nil), blobBefore.Value()...)
	if err := delivery.message.Term(); err != nil {
		t.Fatal(err)
	}
	round13SetSettledMarker(t, consumer.stateStore, delivery.streamSequence)
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	barrier := &round13AfterGetMsgJetStream{
		JetStreamContext: restarted.jetstream, stream: config.IsolationStream,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	restarted.jetstream = barrier
	done := make(chan error, 1)
	go func() {
		_, fetchErr := restarted.Fetch(context.Background())
		done <- fetchErr
	}()
	select {
	case <-barrier.entered:
	case <-time.After(10 * time.Second):
		close(barrier.release)
		t.Fatal("restart reconciliation did not reach the post-validation deletion window")
	}
	if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
		close(barrier.release)
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
		close(barrier.release)
		t.Fatal(err)
	}
	close(barrier.release)
	if fetchErr := <-done; !errors.Is(fetchErr, ErrNoIngestMessages) && !retryableIsolationRecoveryError(fetchErr) {
		t.Fatalf("restart reconciliation first bounded turn error=%v", fetchErr)
	}
	round14WaitRetainedRecovery(t, restarted, 15*time.Second)
	if _, err := restarted.stateStore.Get(parkedStateKey(delivery.streamSequence)); err != nil {
		t.Fatalf("restart reconciliation deleted its only durable recovery proof: %v", err)
	}
	stored, err := jetstream.GetMsg(config.IsolationStream, 1)
	if err != nil || stored.Subject != intent.Subject || stored.Header.Get(nats.MsgIdHdr) != intent.MessageID ||
		!bytes.Equal(stored.Data, intent.Payload) {
		t.Fatalf("restart retained-proof exact evidence=%+v err=%v", stored, err)
	}
	blobAfter, err := restarted.evidenceStore.Get(blobKey)
	if err != nil || !bytes.Equal(blobAfter.Value(), blobBytes) {
		t.Fatalf("restart retained-proof immutable blob changed: err=%v", err)
	}
}

type round13RetryingKeyValue struct {
	nats.KeyValue
	mu       sync.Mutex
	failures []error
	repeat   error
	calls    int
}

func (store *round13RetryingKeyValue) Get(key string) (nats.KeyValueEntry, error) {
	if !strings.HasPrefix(key, "terminal_intent.v1.") {
		return store.KeyValue.Get(key)
	}
	store.mu.Lock()
	store.calls++
	var err error
	if len(store.failures) != 0 {
		err = store.failures[0]
		store.failures = store.failures[1:]
	} else {
		err = store.repeat
	}
	store.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return store.KeyValue.Get(key)
}

func (store *round13RetryingKeyValue) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls
}

func TestOBSUsageARound13PostTermRebuildFailuresEnterRetryScheduler(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round13-retry-matrix")
	defer consumer.Close()
	_, _ = round7ConfirmEvidence(t, sink, delivery)
	if err := delivery.message.Term(); err != nil {
		t.Fatal(err)
	}
	state := round13SetSettledMarker(t, consumer.stateStore, delivery.streamSequence)
	if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
		t.Fatal(err)
	}
	retrying := &round13RetryingKeyValue{KeyValue: sink.evidenceStore, failures: []error{
		context.DeadlineExceeded, nats.ErrTimeout, nats.ErrNoResponders, nats.ErrDisconnected,
		nats.ErrConnectionClosed, nats.ErrStreamNotFound, nats.ErrKeyExists,
	}}
	sink.evidenceStore = retrying
	consumer.resumeTerminalEvidenceRecovery(delivery, state)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		remaining, queued, workers := round11RecoveryCounts(sink)
		info, infoErr := jetstream.StreamInfo(config.IsolationStream)
		if retrying.callCount() >= 9 && remaining == 0 && queued == 0 && workers == 0 &&
			infoErr == nil && info.State.Msgs == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	remaining, queued, workers := round11RecoveryCounts(sink)
	info, err := jetstream.StreamInfo(config.IsolationStream)
	t.Fatalf("post-Term retry matrix calls=%d recovery=%d/%d/%d evidence=%+v err=%v",
		retrying.callCount(), remaining, queued, workers, info, err)
}

func TestOBSUsageARound13CloseCancelsPreEnqueueRetryAndOpenFailsClosed(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	consumer, sink, delivery := round7MalformedDelivery(t, connection, jetstream, config, "round13-close-retry")
	_, _ = round7ConfirmEvidence(t, sink, delivery)
	if err := delivery.message.Term(); err != nil {
		t.Fatal(err)
	}
	state := round13SetSettledMarker(t, consumer.stateStore, delivery.streamSequence)
	if err := jetstream.DeleteStream(config.IsolationStream); err != nil {
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(expectedIsolationStream(config)); err != nil {
		t.Fatal(err)
	}
	retrying := &round13RetryingKeyValue{KeyValue: sink.evidenceStore, repeat: nats.ErrTimeout}
	sink.evidenceStore = retrying
	consumer.resumeTerminalEvidenceRecovery(delivery, state)
	deadline := time.Now().Add(2 * time.Second)
	for retrying.callCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if retrying.callCount() < 2 {
		t.Fatalf("post-Term rebuild was not independently retried: calls=%d", retrying.callCount())
	}
	closed := make(chan error, 1)
	go func() { closed <- consumer.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel and join pre-enqueue recovery backoff")
	}
	remaining, queued, workers := round11RecoveryCounts(sink)
	if remaining != 0 || queued != 0 || workers != 0 {
		t.Fatalf("Close left recovery=%d/%d/%d", remaining, queued, workers)
	}
	restarted, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if deliveries, fetchErr := restarted.Fetch(context.Background()); fetchErr == nil || len(deliveries) != 0 {
		t.Fatalf("restart without durable encrypted intent did not fail closed: deliveries=%d err=%v", len(deliveries), fetchErr)
	}
	if _, err := restarted.stateStore.Get(parkedStateKey(delivery.streamSequence)); err != nil {
		t.Fatalf("restart lost the retained marker while exact intent storage is blocked: %v", err)
	}
}

func TestOBSUsageARound14AESGCMIsolationKeyProviderOwnsAndClearsKEK(t *testing.T) {
	callerKey := bytes.Repeat([]byte{0x5a}, isolationCipherKeySize)
	providerValue, err := NewAESGCMIsolationKeyProvider("analytics/evidence-key-v1", callerKey)
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := providerValue.(*aesGCMIsolationKeyProvider)
	if !ok {
		t.Fatalf("provider type=%T", providerValue)
	}
	clear(callerKey)
	dek := bytes.Repeat([]byte{0x31}, isolationCipherKeySize)
	wrapped, err := provider.WrapDEK(context.Background(), "analytics/evidence-key-v1", dek)
	if err != nil || bytes.Contains(wrapped, dek) {
		t.Fatalf("wrap err=%v plaintext_present=%t", err, bytes.Contains(wrapped, dek))
	}
	clear(dek)
	unwrapped, err := provider.UnwrapDEK(context.Background(), "analytics/evidence-key-v1", wrapped)
	if err != nil || !bytes.Equal(unwrapped, bytes.Repeat([]byte{0x31}, isolationCipherKeySize)) {
		t.Fatalf("unwrap err=%v value=%x", err, sha256.Sum256(unwrapped))
	}
	clear(unwrapped)

	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 1
	if plaintext, err := provider.UnwrapDEK(context.Background(), "analytics/evidence-key-v1", tampered); err == nil || len(plaintext) != 0 {
		clear(plaintext)
		t.Fatal("tampered wrapped DEK did not fail closed")
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(provider.wrappingKey, make([]byte, isolationCipherKeySize)) {
		t.Fatal("provider Close did not clear its owned KEK")
	}
	if _, err := provider.WrapDEK(context.Background(), "analytics/evidence-key-v1", bytes.Repeat([]byte{1}, isolationCipherKeySize)); err == nil {
		t.Fatal("closed provider accepted wrapping")
	}
}

func TestOBSUsageARound14AESGCMIsolationKeyProviderRejectsInvalidInputs(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x23}, isolationCipherKeySize)
	for _, keyID := range []string{"", " key", "key ", "key\n", string([]byte{0xff}), strings.Repeat("k", 129)} {
		if provider, err := NewAESGCMIsolationKeyProvider(keyID, validKey); err == nil || provider != nil {
			t.Fatalf("invalid key ID %q provider=%T err=%v", keyID, provider, err)
		}
	}
	for _, size := range []int{0, 16, 24, 31, 33} {
		if provider, err := NewAESGCMIsolationKeyProvider("analytics/evidence-key-v1", make([]byte, size)); err == nil || provider != nil {
			t.Fatalf("invalid KEK size=%d provider=%T err=%v", size, provider, err)
		}
	}
	provider, err := NewAESGCMIsolationKeyProvider("analytics/evidence-key-v1", validKey)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRound14IsolationProvider(t, provider)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.ActiveKeyID(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel ActiveKeyID err=%v", err)
	}
	if _, err := provider.WrapDEK(cancelled, "analytics/evidence-key-v1", make([]byte, isolationCipherKeySize)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel WrapDEK err=%v", err)
	}
}

func TestOBSUsageARound14EvidenceBucketIsExactAndRuntimeVerifyOnly(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	provider, err := NewAESGCMIsolationKeyProvider("analytics/evidence-key-v1", bytes.Repeat([]byte{7}, isolationCipherKeySize))
	if err != nil {
		t.Fatal(err)
	}
	config.IsolationKeyProvider = provider
	defer closeRound14IsolationProvider(t, provider)
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	defer jetstream.DeleteKeyValue(isolationEvidenceBucketName(config))
	bucket := isolationEvidenceBucketName(config)
	if bucket == "" || (config.Stream == DefaultIngestStream && config.Durable == DefaultIngestDurable &&
		bucket != "AIEVIDENCE_2dcd3c381ead92f3") {
		t.Fatalf("evidence bucket=%q", bucket)
	}
	if err := EnsureIngestJetStream(context.Background(), connection, config); err == nil {
		t.Fatal("runtime created missing evidence bucket")
	}
	if _, err := jetstream.StreamInfo("KV_" + bucket); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("missing evidence bucket was mutated: %v", err)
	}
	provisionRound14EvidenceStore(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	info, err := jetstream.StreamInfo("KV_" + bucket)
	if err != nil {
		t.Fatal(err)
	}
	wantSubject := "$KV." + bucket + ".>"
	if info.Config.Name != "KV_"+bucket || !slices.Equal(info.Config.Subjects, []string{wantSubject}) ||
		info.Config.Retention != nats.LimitsPolicy || info.Config.Storage != nats.FileStorage ||
		info.Config.MaxMsgs != -1 || info.Config.MaxMsgsPerSubject != 1 || info.Config.MaxAge != 0 ||
		info.Config.MaxMsgSize != isolationEvidenceMaxValueSize || info.Config.MaxBytes != config.IsolationMaxBytes ||
		info.Config.Replicas != config.Replicas || info.Config.Discard != nats.DiscardNew ||
		!info.Config.AllowRollup || !info.Config.DenyDelete || !info.Config.AllowDirect || info.Config.NoAck ||
		info.Config.Sealed || info.Config.DiscardNewPerSubject {
		t.Fatalf("evidence bucket config=%+v", info.Config)
	}
	if err := jetstream.DeleteKeyValue(bucket); err != nil {
		t.Fatal(err)
	}
	if consumer, err := NewNATSIngestConsumer(connection, config); err == nil || consumer != nil {
		t.Fatalf("missing evidence bucket consumer=%+v err=%v", consumer, err)
	}
	if _, err := jetstream.StreamInfo("KV_" + bucket); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("runtime recreated missing evidence bucket: %v", err)
	}
	_, err = jetstream.CreateKeyValue(&nats.KeyValueConfig{
		Bucket: bucket, History: 1, TTL: 0, MaxValueSize: isolationEvidenceMaxValueSize,
		MaxBytes: config.IsolationMaxBytes - 1, Storage: nats.FileStorage, Replicas: config.Replicas,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sink, err := NewNATSIsolationSink(connection, config); err == nil || sink != nil {
		t.Fatalf("mismatched evidence bucket sink=%+v err=%v", sink, err)
	}
	after, err := jetstream.StreamInfo("KV_" + bucket)
	if err != nil || after.Config.MaxBytes != config.IsolationMaxBytes-1 {
		t.Fatalf("runtime changed mismatched evidence bucket: info=%+v err=%v", after, err)
	}
}

func closeRound14IsolationProvider(t *testing.T, provider IsolationKeyProvider) {
	t.Helper()
	closer, ok := provider.(interface{ Close() error })
	if !ok {
		t.Fatal("AES-GCM isolation provider does not expose lifecycle close")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
}

func provisionRound14EvidenceStore(t *testing.T, jetstream nats.JetStreamContext, config JetStreamConfig) {
	t.Helper()
	_, err := jetstream.CreateKeyValue(&nats.KeyValueConfig{
		Bucket: isolationEvidenceBucketName(config), History: 1, TTL: 0,
		MaxValueSize: isolationEvidenceMaxValueSize, MaxBytes: config.IsolationMaxBytes,
		Storage: nats.FileStorage, Replicas: config.Replicas,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOBSUsageARound14EvidenceBucketRejectsBehaviorDrift(t *testing.T) {
	config := obsUsageAJetStreamConfig()
	tests := map[string]func(*nats.StreamConfig){
		"subject":                 func(value *nats.StreamConfig) { value.Subjects = []string{"$KV.wrong.>"} },
		"retention":               func(value *nats.StreamConfig) { value.Retention = nats.WorkQueuePolicy },
		"history":                 func(value *nats.StreamConfig) { value.MaxMsgsPerSubject = 2 },
		"ttl":                     func(value *nats.StreamConfig) { value.MaxAge = time.Second },
		"max value":               func(value *nats.StreamConfig) { value.MaxMsgSize-- },
		"max bytes":               func(value *nats.StreamConfig) { value.MaxBytes-- },
		"replicas":                func(value *nats.StreamConfig) { value.Replicas++ },
		"storage":                 func(value *nats.StreamConfig) { value.Storage = nats.MemoryStorage },
		"discard":                 func(value *nats.StreamConfig) { value.Discard = nats.DiscardOld },
		"no ack":                  func(value *nats.StreamConfig) { value.NoAck = true },
		"sealed":                  func(value *nats.StreamConfig) { value.Sealed = true },
		"allow rollup":            func(value *nats.StreamConfig) { value.AllowRollup = false },
		"discard new per subject": func(value *nats.StreamConfig) { value.DiscardNewPerSubject = true },
		"deny delete":             func(value *nats.StreamConfig) { value.DenyDelete = false },
		"allow direct":            func(value *nats.StreamConfig) { value.AllowDirect = false },
		"duplicate window":        func(value *nats.StreamConfig) { value.Duplicates = time.Minute },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			actual := expectedEvidenceStore(config)
			mutate(&actual)
			if sameEvidenceStore(&nats.StreamInfo{Config: actual}, config) {
				t.Fatalf("accepted evidence bucket %s drift", name)
			}
		})
	}
	if !sameEvidenceStore(&nats.StreamInfo{Config: expectedEvidenceStore(config)}, config) {
		t.Fatal("exact evidence bucket was rejected")
	}
}

type round14FailCreateKeyValue struct {
	nats.KeyValue
	err error
}

func (store round14FailCreateKeyValue) Create(string, []byte) (uint64, error) {
	return 0, store.err
}

func TestOBSUsageARound14ExactEncryptedIntentIsImmutableAndFailClosed(t *testing.T) {
	connection, jetstream := connectRound7JetStream(t)
	config := obsUsageAJetStreamConfig()
	wrappingKey := bytes.Repeat([]byte{0x41}, isolationCipherKeySize)
	provider, err := NewAESGCMIsolationKeyProvider("analytics/evidence-key-v1", wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	config.IsolationKeyProvider = provider
	defer closeRound14IsolationProvider(t, provider)
	defer cleanupOBSUsageAJetStream(t, jetstream, config)
	defer jetstream.DeleteKeyValue(isolationEvidenceBucketName(config))
	provisionRound14EvidenceStore(t, jetstream, config)
	if err := ensureProvisionedOBSUsageAJetStream(connection, config); err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"client_secret":"round14-visible-secret"`)
	consumer, sink, delivery := round14MalformedDelivery(t, connection, jetstream, config, "round14-evidence", secret)
	defer consumer.Close()
	record := isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC())
	intent, err := sink.prepareTerminalEvidence(context.Background(), delivery, record)
	if err != nil {
		t.Fatal(err)
	}
	key := isolationEvidenceBlobKey(consumer.streamCreated, delivery.streamSequence)
	entry, err := sink.evidenceStore.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(entry.Value(), secret) || bytes.Contains(entry.Value(), wrappingKey) ||
		bytes.Contains(entry.Value(), []byte(base64.StdEncoding.EncodeToString(secret))) ||
		bytes.Contains(entry.Value(), []byte(base64.RawStdEncoding.EncodeToString(secret))) ||
		bytes.Contains(entry.Value(), []byte(base64.StdEncoding.EncodeToString(wrappingKey))) ||
		bytes.Contains(entry.Value(), []byte(base64.RawStdEncoding.EncodeToString(wrappingKey))) {
		t.Fatal("durable evidence blob contains plaintext wire or KEK")
	}
	decoded, err := decodeIsolationEvidenceBlob(entry.Value(), consumer.streamCreated, delivery.streamSequence, config.IsolationStream)
	if err != nil || decoded.Subject != intent.Subject || decoded.MessageID != intent.MessageID ||
		!bytes.Equal(decoded.Payload, intent.Payload) || decoded.PayloadSHA256 != intent.PayloadSHA256 {
		t.Fatalf("decoded evidence intent=%+v err=%v", decoded, err)
	}
	mutated := append([]byte(nil), entry.Value()...)
	mutated[len(mutated)-1] ^= 1
	if _, err := decodeIsolationEvidenceBlob(mutated, consumer.streamCreated, delivery.streamSequence, config.IsolationStream); err == nil {
		t.Fatal("tampered evidence blob did not fail closed")
	}
	if err := delivery.message.Term(); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}

	wrongConsumer, _, wrongDelivery := round14MalformedDelivery(t, connection, jetstream, config, "round14-wrong", []byte("{"))
	wrongKey := isolationEvidenceBlobKey(wrongConsumer.streamCreated, wrongDelivery.streamSequence)
	wrongRecord := isolationRecord(wrongDelivery, RejectInvalidJSON, time.Now().UTC())
	wrongRecord.Wire = &IsolationWire{
		Subject: wrongRecord.Wire.Subject, Payload: append([]byte(nil), wrongRecord.Wire.Payload...),
		Headers: slices.Clone(wrongRecord.Wire.Headers),
	}
	for index := range wrongRecord.Wire.Headers {
		if wrongRecord.Wire.Headers[index].Name == ingestInstallHeader {
			wrongRecord.Wire.Headers[index].Value = "round14-wrong-installation"
		}
	}
	wrongIntent, _, err := sink.buildIsolationIntent(context.Background(), wrongRecord, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrongIntent.Payload)
	wrongBlob, err := encodeIsolationEvidenceBlob(
		wrongIntent, wrongConsumer.streamCreated, wrongDelivery.streamSequence,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrongBlob)
	if _, err := sink.evidenceStore.Create(wrongKey, wrongBlob); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.prepareTerminalEvidence(context.Background(), wrongDelivery,
		isolationRecord(wrongDelivery, RejectInvalidJSON, time.Now().UTC())); err == nil {
		t.Fatal("same immutable key with wrong evidence bytes did not fail closed")
	}
	if err := wrongDelivery.message.Term(); err != nil {
		t.Fatal(err)
	}
	if err := wrongConsumer.Close(); err != nil {
		t.Fatal(err)
	}

	fullConsumer, _, fullDelivery := round14MalformedDelivery(t, connection, jetstream, config, "round14-full", []byte("{"))
	defer fullConsumer.Close()
	sink.evidenceStore = round14FailCreateKeyValue{KeyValue: sink.evidenceStore, err: errors.New("maximum bytes exceeded")}
	if _, err := sink.prepareTerminalEvidence(context.Background(), fullDelivery,
		isolationRecord(fullDelivery, RejectInvalidJSON, time.Now().UTC())); err == nil {
		t.Fatal("full evidence bucket did not fail closed")
	}
	marker, err := fullConsumer.stateStore.Get(parkedStateKey(fullDelivery.streamSequence))
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeParkedDeliveryState(marker.Value(), fullDelivery.streamSequence)
	if err != nil || state.Phase != parkedPhaseDelivery || state.TermSent {
		t.Fatalf("full bucket marker=%+v err=%v", state, err)
	}
}

func round14MalformedDelivery(
	t *testing.T,
	connection *nats.Conn,
	jetstream nats.JetStreamContext,
	config JetStreamConfig,
	messageID string,
	payload []byte,
) (*NATSIngestConsumer, *NATSIsolationSink, *natsIngestDelivery) {
	t.Helper()
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	message := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
	message.Header.Set(nats.MsgIdHdr, messageID)
	setIntegrationAuthority(message, testConfigVersionID)
	message.Data = append([]byte(nil), payload...)
	ack, err := jetstream.PublishMsg(message, nats.ExpectStream(config.Stream))
	if err != nil || ack == nil || ack.Stream != config.Stream || ack.Sequence == 0 {
		t.Fatalf("publish malformed message ack=%+v err=%v", ack, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		deliveries, fetchErr := consumer.Fetch(context.Background())
		if fetchErr == nil && len(deliveries) == 1 {
			delivery := deliveries[0].(*natsIngestDelivery)
			if delivery.MessageID() != messageID {
				t.Fatalf("fetched message ID=%q want=%q", delivery.MessageID(), messageID)
			}
			return consumer, sink, delivery
		}
		if !errors.Is(fetchErr, ErrNoIngestMessages) || time.Now().After(deadline) {
			t.Fatalf("fetch malformed message deliveries=%d err=%v", len(deliveries), fetchErr)
		}
	}
}

func round14WaitRetainedRecovery(t *testing.T, consumer *NATSIngestConsumer, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		deliveries, err := consumer.Fetch(context.Background())
		if errors.Is(err, ErrNoIngestMessages) && len(deliveries) == 0 {
			return
		}
		if len(deliveries) != 0 || !retryableIsolationRecoveryError(err) || time.Now().After(deadline) {
			t.Fatalf("retained evidence recovery deliveries=%d err=%v", len(deliveries), err)
		}
	}
}

func round13SetSettledMarker(
	t *testing.T,
	store nats.KeyValue,
	sequence uint64,
) parkedDeliveryState {
	t.Helper()
	key := parkedStateKey(sequence)
	entry, err := store.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeParkedDeliveryState(entry.Value(), sequence)
	if err != nil {
		t.Fatal(err)
	}
	state.Phase = parkedPhaseSettled
	state.TermSent = true
	value, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(key, value, entry.Revision()); err != nil {
		t.Fatal(err)
	}
	return state
}

func mustParseRound12ParkedSequence(key string) uint64 {
	sequence, err := parseParkedStateKey(key)
	if err != nil {
		panic(err)
	}
	return sequence
}

// round12WaitParkedMarkerSettled 等终态恢复收敛：终态 Term 后 marker 保留为 settled+TermSent，
// 作为唯一的持久恢复证明（ingest_nats.go settle 的 TermPending 分支不删，Round6/Round13 断言保留）。
func round12WaitParkedMarkerSettled(t *testing.T, store nats.KeyValue, sequence uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		entry, err := store.Get(parkedStateKey(sequence))
		var state parkedDeliveryState
		if err == nil {
			state, err = decodeParkedDeliveryState(entry.Value(), sequence)
			if err == nil && state.Phase == parkedPhaseSettled && state.TermSent {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("parked marker was not settled for sequence=%d: state=%+v err=%v", sequence, state, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func round11WaitEvidenceEpoch(
	t *testing.T,
	store nats.KeyValue,
	sequence uint64,
	created time.Time,
	timeout time.Duration,
) parkedDeliveryState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	want := created.UTC().Format(time.RFC3339Nano)
	var last parkedDeliveryState
	for {
		entry, err := store.Get(parkedStateKey(sequence))
		if err == nil {
			state, decodeErr := decodeParkedDeliveryState(entry.Value(), sequence)
			last = state
			if decodeErr == nil && state.EvidenceConfirmed && state.EvidenceStreamCreated == want {
				return state
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal evidence epoch was not confirmed: want=%s state=%+v err=%v", want, last, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func round10WaitEvidenceConfirmed(
	t *testing.T,
	store nats.KeyValue,
	sequence uint64,
	timeout time.Duration,
) parkedDeliveryState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last parkedDeliveryState
	for {
		entry, err := store.Get(parkedStateKey(sequence))
		if err == nil {
			state, decodeErr := decodeParkedDeliveryState(entry.Value(), sequence)
			last = state
			if decodeErr == nil && state.EvidenceConfirmed {
				return state
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal evidence was not confirmed for sequence=%d state=%+v: %v", sequence, last, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func round10WaitRecoveryAttempts(
	t *testing.T,
	store *round10FlakyRecoveryKeyValue,
	want int,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		gets, _ := store.attempts()
		if gets >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery reload attempts=%d want>=%d", gets, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func round10WaitRecoveringEmpty(t *testing.T, sink *NATSIsolationSink, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		sink.recoveryMu.Lock()
		remaining := len(sink.recovering)
		queued := len(sink.recoveryQueue)
		workers := sink.recoveryWorkers
		sink.recoveryMu.Unlock()
		if remaining == 0 && queued == 0 && workers == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery scheduler did not shut down: remaining=%d queued=%d workers=%d", remaining, queued, workers)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func round7ConfirmEvidence(
	t *testing.T,
	sink *NATSIsolationSink,
	delivery *natsIngestDelivery,
) (isolationPublishIntent, uint64) {
	t.Helper()
	intent, err := sink.prepareTerminalEvidence(
		context.Background(), delivery, isolationRecord(delivery, RejectInvalidJSON, time.Now().UTC()),
	)
	if err != nil {
		t.Fatal(err)
	}
	sequence, err := sink.publishEvidenceIntent(context.Background(), intent)
	if err != nil || sequence == 0 {
		t.Fatalf("publish evidence sequence=%d err=%v", sequence, err)
	}
	if err := sink.confirmTerminalEvidence(context.Background(), delivery, intent, sequence); err != nil {
		t.Fatal(err)
	}
	return intent, sequence
}

func connectRound7JetStream(t *testing.T) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()
	connection, _ := connectJetStreamBlockerProof(t)
	jetstream, err := connection.JetStream(nats.MaxWait(15 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return connection, jetstream
}

func round7MalformedDelivery(
	t *testing.T,
	connection *nats.Conn,
	jetstream nats.JetStreamContext,
	config JetStreamConfig,
	messageID string,
) (*NATSIngestConsumer, *NATSIsolationSink, *natsIngestDelivery) {
	t.Helper()
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	message := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
	message.Header.Set(nats.MsgIdHdr, messageID)
	setIntegrationAuthority(message, testConfigVersionID)
	message.Data = []byte("{")
	ack, err := jetstream.PublishMsg(message, nats.ExpectStream(config.Stream))
	if err != nil || ack == nil || ack.Stream != config.Stream || ack.Sequence == 0 {
		t.Fatalf("publish malformed message ack=%+v err=%v", ack, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		deliveries, fetchErr := consumer.Fetch(context.Background())
		if fetchErr == nil && len(deliveries) == 1 {
			delivery := deliveries[0].(*natsIngestDelivery)
			if delivery.streamSequence != ack.Sequence {
				t.Fatalf("fetched sequence=%d PubAck sequence=%d", delivery.streamSequence, ack.Sequence)
			}
			return consumer, sink, delivery
		}
		if !errors.Is(fetchErr, ErrNoIngestMessages) || time.Now().After(deadline) {
			t.Fatalf("fetch malformed message deliveries=%d err=%v", len(deliveries), fetchErr)
		}
	}
}

func round7HeaderNames(header nats.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func round6MalformedDelivery(
	t *testing.T,
	connection *nats.Conn,
	jetstream nats.JetStreamContext,
	config JetStreamConfig,
	messageID string,
) (*NATSIngestConsumer, *NATSIsolationSink, *natsIngestDelivery) {
	t.Helper()
	consumer, err := NewNATSIngestConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewNATSIsolationSink(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	message := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
	message.Header.Set(nats.MsgIdHdr, messageID)
	setIntegrationAuthority(message, testConfigVersionID)
	message.Data = []byte("{")
	ack, err := jetstream.PublishMsg(message)
	if err != nil || ack == nil || ack.Stream != config.Stream || ack.Sequence == 0 {
		t.Fatalf("publish malformed message ack=%+v err=%v", ack, err)
	}
	deliveries, err := consumer.Fetch(context.Background())
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("fetch malformed message deliveries=%d err=%v", len(deliveries), err)
	}
	return consumer, sink, deliveries[0].(*natsIngestDelivery)
}

func round6WaitDelivery(t *testing.T, consumer *NATSIngestConsumer, timeout time.Duration) IngestDelivery {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		deliveries, err := consumer.Fetch(context.Background())
		if err == nil && len(deliveries) == 1 {
			return deliveries[0]
		}
		if !errors.Is(err, ErrNoIngestMessages) || time.Now().After(deadline) {
			t.Fatalf("wait delivery deliveries=%d err=%v", len(deliveries), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func round6ParkedKeyCount(keys []string) int {
	count := 0
	for _, key := range keys {
		if strings.HasPrefix(key, "parked.") {
			count++
		}
	}
	return count
}
