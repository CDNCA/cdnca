package analytics

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type ackRecoveryContextDelivery struct {
	ack      func(context.Context) error
	ackCalls int
	nakCalls int
	nakErr   error
}

func (*ackRecoveryContextDelivery) Subject() string        { return "" }
func (*ackRecoveryContextDelivery) Data() []byte           { return nil }
func (*ackRecoveryContextDelivery) MessageID() string      { return "" }
func (*ackRecoveryContextDelivery) Attempts() uint64       { return 1 }
func (*ackRecoveryContextDelivery) StreamSequence() uint64 { return 1 }
func (delivery *ackRecoveryContextDelivery) Ack(ctx context.Context) error {
	delivery.ackCalls++
	return delivery.ack(ctx)
}
func (delivery *ackRecoveryContextDelivery) Nak(context.Context, time.Duration) error {
	delivery.nakCalls++
	return delivery.nakErr
}
func (*ackRecoveryContextDelivery) Term(context.Context) error { return nil }

type ackRecoveryContextAuthority struct {
	*recordingIngestHistoryAuthorityV1

	mu                    sync.Mutex
	observationErr        error
	observationCalls      int
	observationContextErr error
	scheduleErr           error
	scheduleCalls         int
	scheduleContext       context.Context
	scheduleContextErr    error
	scheduleDeadline      time.Time
	scheduleCalledAt      time.Time
	scheduleGeneration    IngestHistoryGenerationV1
}

func (history *ackRecoveryContextAuthority) MarkBrokerAckObserved(ctx context.Context, _ IngestReceiptKeyV1) error {
	history.record("broker-ack-observed")
	history.mu.Lock()
	defer history.mu.Unlock()
	history.observationCalls++
	history.observationContextErr = ctx.Err()
	return history.observationErr
}

func (history *ackRecoveryContextAuthority) ScheduleRecovery(
	ctx context.Context,
	generation IngestHistoryGenerationV1,
) error {
	history.record("recovery-scheduled")
	history.mu.Lock()
	defer history.mu.Unlock()
	history.scheduleCalls++
	history.scheduleContext = ctx
	history.scheduleContextErr = ctx.Err()
	history.scheduleDeadline, _ = ctx.Deadline()
	history.scheduleCalledAt = time.Now()
	history.scheduleGeneration = generation
	if history.scheduleErr != nil {
		return history.scheduleErr
	}
	return ctx.Err()
}

func TestIngestProcessorAckUnknownOutcomeSchedulesRecoveryWithFreshContext(t *testing.T) {
	const (
		operationTimeout  = 100 * time.Millisecond
		settlementTimeout = 10 * time.Millisecond
	)
	generation := authorityGenerationV1()
	newFixture := func(t *testing.T) (*IngestProcessor, *ackRecoveryContextAuthority) {
		t.Helper()
		history := &ackRecoveryContextAuthority{
			recordingIngestHistoryAuthorityV1: newRecordingIngestHistoryAuthorityV1(t, generation),
		}
		return &IngestProcessor{
			operationTimeout:  operationTimeout,
			history:           history,
			historyGeneration: generation,
		}, history
	}
	newChunk := func(delivery IngestDelivery) *ingestChunk {
		return &ingestChunk{items: []*parsedIngest{{
			deliveries: []IngestDelivery{delivery},
			receipt: IngestReceiptV1{Key: IngestReceiptKeyV1{
				StreamSequence: generation.HistoryStartSequence,
			}},
			receiptState: IngestReceiptStatePrepared,
		}}}
	}
	newDelivery := func(history *ackRecoveryContextAuthority, ack func(context.Context) error) *ackRecoveryContextDelivery {
		return &ackRecoveryContextDelivery{ack: func(ctx context.Context) error {
			history.record("nats-ack")
			return ack(ctx)
		}}
	}
	assertFreshRecoveryContext := func(t *testing.T, history *ackRecoveryContextAuthority) {
		t.Helper()
		history.mu.Lock()
		defer history.mu.Unlock()
		if history.scheduleCalls != 1 {
			t.Fatalf("ScheduleRecovery calls = %d, want 1", history.scheduleCalls)
		}
		if history.scheduleGeneration != generation {
			t.Fatalf("ScheduleRecovery generation = %#v, want %#v", history.scheduleGeneration, generation)
		}
		if history.scheduleContextErr != nil {
			t.Fatalf("ScheduleRecovery context was already done: %v", history.scheduleContextErr)
		}
		if history.scheduleDeadline.IsZero() || !history.scheduleDeadline.After(history.scheduleCalledAt) ||
			history.scheduleDeadline.After(history.scheduleCalledAt.Add(operationTimeout)) {
			t.Fatalf("ScheduleRecovery deadline = %s at %s, want fresh deadline bounded by %s",
				history.scheduleDeadline, history.scheduleCalledAt, operationTimeout)
		}
		if history.scheduleContext == nil || !errors.Is(history.scheduleContext.Err(), context.Canceled) {
			t.Fatalf("ScheduleRecovery context error after call = %v, want context canceled",
				history.scheduleContext.Err())
		}
	}

	t.Run("ACK failure after settlement deadline", func(t *testing.T) {
		processor, history := newFixture(t)
		delivery := newDelivery(history, func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		})
		settlementCtx, cancel := context.WithTimeout(context.Background(), settlementTimeout)
		defer cancel()
		result := IngestBatchResult{}

		err := processor.ackChunk(settlementCtx, newChunk(delivery), &result)
		if !errors.Is(err, context.DeadlineExceeded) || result.Acknowledged != 0 || delivery.ackCalls != 1 ||
			history.observationCalls != 0 || history.scheduleCalls != 1 ||
			authorityOperationsV1(history.recordingIngestHistoryAuthorityV1) != "recovery-scheduled,nats-ack" {
			t.Fatalf("error=%v result=%#v ACKs=%d observations=%d", err, result, delivery.ackCalls, history.observationCalls)
		}
		assertFreshRecoveryContext(t, history)
	})

	t.Run("ACK success after deadline followed by observation failure", func(t *testing.T) {
		observationErr := errors.New("broker ACK observation unavailable")
		processor, history := newFixture(t)
		history.observationErr = observationErr
		delivery := newDelivery(history, func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		})
		settlementCtx, cancel := context.WithTimeout(context.Background(), settlementTimeout)
		defer cancel()
		result := IngestBatchResult{}

		err := processor.ackChunk(settlementCtx, newChunk(delivery), &result)
		if !errors.Is(err, observationErr) || errors.Is(err, context.DeadlineExceeded) ||
			result.Acknowledged != 1 || delivery.ackCalls != 1 || history.observationCalls != 1 ||
			!errors.Is(history.observationContextErr, context.DeadlineExceeded) || history.scheduleCalls != 1 ||
			authorityOperationsV1(history.recordingIngestHistoryAuthorityV1) != "recovery-scheduled,nats-ack,broker-ack-observed" {
			t.Fatalf("error=%v result=%#v ACKs=%d observations=%d observation_ctx=%v",
				err, result, delivery.ackCalls, history.observationCalls, history.observationContextErr)
		}
		assertFreshRecoveryContext(t, history)
	})

	t.Run("timely ACK and observation follow durable recovery marker", func(t *testing.T) {
		processor, history := newFixture(t)
		delivery := newDelivery(history, func(context.Context) error { return nil })
		settlementCtx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		result := IngestBatchResult{}

		err := processor.ackChunk(settlementCtx, newChunk(delivery), &result)
		if err != nil || result.Acknowledged != 1 || delivery.ackCalls != 1 ||
			history.observationCalls != 1 || history.observationContextErr != nil || history.scheduleCalls != 1 ||
			authorityOperationsV1(history.recordingIngestHistoryAuthorityV1) != "recovery-scheduled,nats-ack,broker-ack-observed" {
			t.Fatalf("error=%v result=%#v ACKs=%d observations=%d observation_ctx=%v recoveries=%d",
				err, result, delivery.ackCalls, history.observationCalls, history.observationContextErr, history.scheduleCalls)
		}
		assertFreshRecoveryContext(t, history)
	})

	t.Run("recovery scheduling failure leaves prepared receipt replayable", func(t *testing.T) {
		scheduleErr := errors.New("durable recovery scheduling unavailable")
		processor, history := newFixture(t)
		history.scheduleErr = scheduleErr
		history.prepared = true
		history.receiveState = IngestReceiptStatePrepared
		delivery := newDelivery(history, func(context.Context) error { return nil })
		result := IngestBatchResult{}

		err := processor.ackChunk(context.Background(), newChunk(delivery), &result)
		if !errors.Is(err, scheduleErr) || result.Acknowledged != 0 || result.Naked != 1 ||
			delivery.ackCalls != 0 || delivery.nakCalls != 1 || history.observationCalls != 0 ||
			history.scheduleCalls != 1 || !history.prepared || history.receiveState != IngestReceiptStatePrepared ||
			authorityOperationsV1(history.recordingIngestHistoryAuthorityV1) != "recovery-scheduled" {
			t.Fatalf("error=%v result=%#v delivery=%#v history=%#v operations=%q", err, result, delivery,
				history, authorityOperationsV1(history.recordingIngestHistoryAuthorityV1))
		}
		assertFreshRecoveryContext(t, history)
	})
}
