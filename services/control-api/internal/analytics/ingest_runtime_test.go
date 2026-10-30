package analytics

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type ingestHistorySnapshotJetStream struct {
	nats.JetStreamContext
	stream   *nats.StreamInfo
	consumer *nats.ConsumerInfo
}

func (jetstream *ingestHistorySnapshotJetStream) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) {
	return jetstream.stream, nil
}

func (jetstream *ingestHistorySnapshotJetStream) ConsumerInfo(string, string, ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	return jetstream.consumer, nil
}

func TestIngestRuntimeReportsHealthyOnlyAfterFullyAcknowledgedBatch(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	runtime := &IngestRuntime{}
	runtime.SetHealthyHandler(func() { calls.Add(1) })

	runtime.reportHealthy(IngestBatchResult{Terminated: 1}, nil)
	runtime.reportHealthy(IngestBatchResult{Acknowledged: 1, Naked: 1}, nil)
	runtime.reportHealthy(IngestBatchResult{Acknowledged: 1}, errors.New("partial settlement"))
	if calls.Load() != 0 {
		t.Fatalf("healthy calls before complete acknowledgement = %d", calls.Load())
	}

	runtime.reportHealthy(IngestBatchResult{Acknowledged: 1}, nil)
	if calls.Load() != 1 {
		t.Fatalf("healthy calls after complete acknowledgement = %d", calls.Load())
	}
}

func TestIngestRuntimeProcessingFailureRequiresAcknowledgedRecovery(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	runtime := &IngestRuntime{}
	runtime.SetHealthyHandler(func() { calls.Add(1) })

	runtime.reportHealthy(IngestBatchResult{Fetched: 1, Naked: 1}, nil)
	runtime.reportHealthy(IngestBatchResult{}, ErrNoIngestMessages)
	runtime.reportHealthy(IngestBatchResult{Fetched: 1}, errors.New("settlement failed"))
	runtime.reportHealthy(IngestBatchResult{}, ErrNoIngestMessages)
	if calls.Load() != 0 {
		t.Fatalf("empty fetch cleared processing degradation: calls=%d", calls.Load())
	}
	runtime.reportHealthy(IngestBatchResult{Acknowledged: 1}, nil)
	if calls.Load() != 1 {
		t.Fatalf("acknowledged recovery calls = %d", calls.Load())
	}
}

func TestIngestRuntimePureFetchFailureRecoversOnEmptyFetch(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	runtime := &IngestRuntime{}
	runtime.SetHealthyHandler(func() { calls.Add(1) })

	runtime.reportHealthy(IngestBatchResult{}, errors.New("fetch failed"))
	runtime.reportHealthy(IngestBatchResult{}, ErrNoIngestMessages)
	if calls.Load() != 1 {
		t.Fatalf("empty fetch recovery calls = %d", calls.Load())
	}
}

func TestIngestRuntimeReconcilesBrokerFloorAndRejectsGenerationChange(t *testing.T) {
	generation := authorityGenerationV1()
	newScheduledHistory := func(t *testing.T) *recordingIngestHistoryAuthorityV1 {
		t.Helper()
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		receipt, err := NewIngestReceiptV1(generation, 41, authorityDecodedIngestV1(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := history.MarkPrepared(context.Background(), receipt); err != nil {
			t.Fatal(err)
		}
		if err := history.ScheduleRecovery(context.Background(), generation); err != nil {
			t.Fatal(err)
		}
		return history
	}
	snapshot := IngestBrokerHistorySnapshotV1{
		Generation: generation, ConsumerAckFloor: 1, StreamAckFloor: 41,
	}

	t.Run("atomic claim allows one runtime and gates completed recovery", func(t *testing.T) {
		history := newScheduledHistory(t)
		brokerEntered := make(chan struct{}, 1)
		releaseBroker := make(chan struct{})
		var brokerCalls atomic.Int32
		newRuntime := func() *IngestRuntime {
			return &IngestRuntime{
				history: history, historyGeneration: generation,
				brokerHistorySnapshot: func(context.Context) (IngestBrokerHistorySnapshotV1, error) {
					brokerCalls.Add(1)
					brokerEntered <- struct{}{}
					<-releaseBroker
					return snapshot, nil
				},
			}
		}
		winner, competitor := newRuntime(), newRuntime()
		var wait sync.WaitGroup
		wait.Add(1)
		var winnerRecovered bool
		var winnerErr error
		go func() {
			defer wait.Done()
			winnerRecovered, winnerErr = winner.RunScheduledHistoryRecovery(context.Background())
		}()
		<-brokerEntered
		if recovered, err := competitor.RunScheduledHistoryRecovery(context.Background()); err != nil || recovered {
			t.Fatalf("competing runtime recovery = (%t, %v), want gated", recovered, err)
		}
		close(releaseBroker)
		wait.Wait()
		if winnerErr != nil || !winnerRecovered || brokerCalls.Load() != 1 || history.recoveryClaimCount != 1 ||
			history.recoveryCompleteCount != 1 || history.recoveryScheduled || history.progress.CommittedStreamAckFloor != 41 {
			t.Fatalf("winner=(%t,%v) broker=%d history=%#v", winnerRecovered, winnerErr, brokerCalls.Load(), history)
		}
		if recovered, err := competitor.RunScheduledHistoryRecovery(context.Background()); err != nil || recovered || brokerCalls.Load() != 1 {
			t.Fatalf("completed recovery rerun = (%t, %v), broker calls=%d", recovered, err, brokerCalls.Load())
		}
	})

	t.Run("reconcile error keeps scheduled fact and lease expiry permits takeover", func(t *testing.T) {
		history := newScheduledHistory(t)
		changed := generation
		changed.ConsumerCreatedUnixNano++
		currentSnapshot := IngestBrokerHistorySnapshotV1{
			Generation: changed, ConsumerAckFloor: 1, StreamAckFloor: 41,
		}
		brokerCalls := 0
		runtime := &IngestRuntime{
			history: history, historyGeneration: generation,
			brokerHistorySnapshot: func(context.Context) (IngestBrokerHistorySnapshotV1, error) {
				brokerCalls++
				return currentSnapshot, nil
			},
		}
		if recovered, err := runtime.RunScheduledHistoryRecovery(context.Background()); recovered || !errors.Is(err, ErrIngestHistoryGenerationChanged) {
			t.Fatalf("generation change recovery = (%t, %v)", recovered, err)
		}
		if history.recoveryCompleteCount != 0 || !history.recoveryScheduled || history.recoveryClaimCount != 1 {
			t.Fatalf("failed recovery consumed durable fact: %#v", history)
		}
		if recovered, err := runtime.RunScheduledHistoryRecovery(context.Background()); err != nil || recovered || brokerCalls != 1 {
			t.Fatalf("live claim rerun = (%t, %v), broker calls=%d", recovered, err, brokerCalls)
		}

		history.advanceRecoveryClock(history.recoveryLease)
		currentSnapshot = snapshot
		restarted := &IngestRuntime{
			history: history, historyGeneration: generation,
			brokerHistorySnapshot: runtime.brokerHistorySnapshot,
		}
		if recovered, err := restarted.RunScheduledHistoryRecovery(context.Background()); err != nil || !recovered {
			t.Fatalf("expired claim takeover = (%t, %v)", recovered, err)
		}
		if brokerCalls != 2 || history.recoveryClaimCount != 2 || history.recoveryCompleteCount != 1 || history.recoveryScheduled {
			t.Fatalf("takeover broker calls=%d history=%#v", brokerCalls, history)
		}
	})
}

func TestNATSIngestHistorySnapshotRejectsLiveGenerationMismatch(t *testing.T) {
	generation := authorityGenerationV1()
	streamCreated := time.Unix(0, int64(generation.StreamCreatedUnixNano)).UTC()
	consumerCreated := time.Unix(0, int64(generation.ConsumerCreatedUnixNano)).UTC()
	newConsumer := func(stream, consumer time.Time) *NATSIngestConsumer {
		return &NATSIngestConsumer{
			jetstream: &ingestHistorySnapshotJetStream{
				stream: &nats.StreamInfo{Created: stream},
				consumer: &nats.ConsumerInfo{
					Created:  consumer,
					AckFloor: nats.SequenceInfo{Consumer: 2, Stream: 42},
				},
			},
			config:        JetStreamConfig{Stream: generation.StreamName, Durable: generation.DurableName, OperationTimeout: time.Second},
			streamCreated: streamCreated, consumerCreated: consumerCreated,
		}
	}
	valid, err := newConsumer(streamCreated, consumerCreated).HistorySnapshot(context.Background(), generation)
	if err != nil || valid.Generation != generation || valid.ConsumerAckFloor != 2 || valid.StreamAckFloor != 42 {
		t.Fatalf("valid snapshot = (%#v, %v)", valid, err)
	}
	for _, test := range []struct {
		name     string
		consumer *NATSIngestConsumer
	}{
		{name: "stream recreated", consumer: newConsumer(streamCreated.Add(time.Nanosecond), consumerCreated)},
		{name: "consumer recreated", consumer: newConsumer(streamCreated, consumerCreated.Add(time.Nanosecond))},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := test.consumer.HistorySnapshot(context.Background(), generation)
			if !errors.Is(err, ErrIngestHistoryGenerationChanged) || snapshot != (IngestBrokerHistorySnapshotV1{}) {
				t.Fatalf("mismatched snapshot = (%#v, %v)", snapshot, err)
			}
		})
	}
}
