package analytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errMissingRecoveryDeadline = errors.New("missing analytics recovery deadline")

type recoveryDeadlineAuthority struct {
	blockStage        string
	succeedAfterBlock bool
	noClaim           bool
	calls             [4]int
	deadlines         [4]time.Time
}

func (history *recoveryDeadlineAuthority) Receive(context.Context, IngestReceiptV1) (IngestReceiptStateV1, error) {
	return 0, ErrInvalidInput
}

func (history *recoveryDeadlineAuthority) MarkPrepared(context.Context, IngestReceiptV1) (IngestHistoryProgressV1, error) {
	return IngestHistoryProgressV1{}, ErrInvalidInput
}

func (history *recoveryDeadlineAuthority) MarkBrokerAckObserved(context.Context, IngestReceiptKeyV1) error {
	return ErrInvalidInput
}

func (history *recoveryDeadlineAuthority) ReconcileBroker(ctx context.Context, _ IngestRecoveryClaimV1, _ IngestBrokerHistorySnapshotV1) (IngestHistoryProgressV1, error) {
	if err := history.record(ctx, 2, "reconcile"); err != nil {
		return IngestHistoryProgressV1{}, err
	}
	return IngestHistoryProgressV1{}, nil
}

func (history *recoveryDeadlineAuthority) ScheduleRecovery(context.Context, IngestHistoryGenerationV1) error {
	return ErrInvalidInput
}

func (history *recoveryDeadlineAuthority) ClaimScheduledRecovery(ctx context.Context, _ IngestHistoryGenerationV1) (IngestRecoveryClaimV1, bool, error) {
	if err := history.record(ctx, 0, "claim"); err != nil {
		return IngestRecoveryClaimV1{}, false, err
	}
	if history.noClaim {
		return IngestRecoveryClaimV1{}, false, nil
	}
	return IngestRecoveryClaimV1{
		RecoveryID: "recovery", ClaimedBy: "worker", Token: "token", LeaseExpiresAt: time.Now().Add(time.Minute),
	}, true, nil
}

func (history *recoveryDeadlineAuthority) CompleteScheduledRecovery(ctx context.Context, _ IngestRecoveryClaimV1) error {
	return history.record(ctx, 3, "complete")
}

func (history *recoveryDeadlineAuthority) record(ctx context.Context, index int, stage string) error {
	history.calls[index]++
	deadline, ok := ctx.Deadline()
	if !ok {
		return errMissingRecoveryDeadline
	}
	history.deadlines[index] = deadline
	if history.blockStage != stage {
		return nil
	}
	<-ctx.Done()
	if history.succeedAfterBlock {
		return nil
	}
	return ctx.Err()
}

func TestIngestRuntimeRecoveryUsesSharedOperationDeadline(t *testing.T) {
	generation := authorityGenerationV1()
	snapshot := IngestBrokerHistorySnapshotV1{Generation: generation, ConsumerAckFloor: 1, StreamAckFloor: 1}
	newRuntime := func(t *testing.T, operationTimeout time.Duration, history *recoveryDeadlineAuthority) *IngestRuntime {
		t.Helper()
		processor := &IngestProcessor{
			operationTimeout:  operationTimeout,
			history:           history,
			historyGeneration: generation,
		}
		runtime, err := NewIngestRuntime(&NATSIngestConsumer{}, processor, nil)
		if err != nil {
			t.Fatal(err)
		}
		runtime.brokerHistorySnapshot = func(ctx context.Context) (IngestBrokerHistorySnapshotV1, error) {
			if err := history.record(ctx, 1, "snapshot"); err != nil {
				return IngestBrokerHistorySnapshotV1{}, err
			}
			return snapshot, nil
		}
		return runtime
	}

	stages := []string{"claim", "snapshot", "reconcile", "complete"}
	for blockedIndex, blockedStage := range stages {
		t.Run(blockedStage+" success after timeout", func(t *testing.T) {
			history := &recoveryDeadlineAuthority{blockStage: blockedStage, succeedAfterBlock: true}
			recovered, err := newRuntime(t, 10*time.Millisecond, history).RunScheduledHistoryRecovery(context.Background())
			if recovered || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("recovery = (%t, %v), want (false, deadline exceeded)", recovered, err)
			}
			for index, calls := range history.calls {
				want := 0
				if index <= blockedIndex {
					want = 1
				}
				if calls != want {
					t.Fatalf("%s calls = %d, want %d after %s timeout", stages[index], calls, want, blockedStage)
				}
			}
		})
	}

	t.Run("claim no result after timeout", func(t *testing.T) {
		history := &recoveryDeadlineAuthority{blockStage: "claim", succeedAfterBlock: true, noClaim: true}
		recovered, err := newRuntime(t, 10*time.Millisecond, history).RunScheduledHistoryRecovery(context.Background())
		if recovered || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("recovery = (%t, %v), want (false, deadline exceeded)", recovered, err)
		}
		if history.calls != [4]int{1, 0, 0, 0} {
			t.Fatalf("calls after no-claim timeout = %v", history.calls)
		}
	})

	t.Run("successful recovery reuses one deadline", func(t *testing.T) {
		history := &recoveryDeadlineAuthority{}
		recovered, err := newRuntime(t, time.Second, history).RunScheduledHistoryRecovery(context.Background())
		if err != nil || !recovered {
			t.Fatalf("recovery = (%t, %v), want success", recovered, err)
		}
		deadline := history.deadlines[0]
		if deadline.IsZero() {
			t.Fatal("claim deadline is zero")
		}
		for index, calls := range history.calls {
			if calls != 1 {
				t.Fatalf("%s calls = %d, want 1", stages[index], calls)
			}
			if !history.deadlines[index].Equal(deadline) {
				t.Fatalf("%s deadline = %v, want shared %v", stages[index], history.deadlines[index], deadline)
			}
		}
	})

	t.Run("pre-canceled caller skips dependencies", func(t *testing.T) {
		history := &recoveryDeadlineAuthority{noClaim: true}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		recovered, err := newRuntime(t, time.Second, history).RunScheduledHistoryRecovery(ctx)
		if recovered || !errors.Is(err, context.Canceled) {
			t.Fatalf("recovery = (%t, %v), want caller cancellation", recovered, err)
		}
		if history.calls != [4]int{} {
			t.Fatalf("calls after caller cancellation = %v", history.calls)
		}
	})

	t.Run("shorter caller deadline remains authoritative", func(t *testing.T) {
		history := &recoveryDeadlineAuthority{blockStage: "claim", succeedAfterBlock: true}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		callerDeadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("caller deadline is missing")
		}
		recovered, err := newRuntime(t, time.Second, history).RunScheduledHistoryRecovery(ctx)
		if recovered || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("recovery = (%t, %v), want caller deadline exceeded", recovered, err)
		}
		if history.calls != [4]int{1, 0, 0, 0} {
			t.Fatalf("calls after caller deadline = %v", history.calls)
		}
		if !history.deadlines[0].Equal(callerDeadline) {
			t.Fatalf("claim deadline = %v, want caller deadline %v", history.deadlines[0], callerDeadline)
		}
	})
}
