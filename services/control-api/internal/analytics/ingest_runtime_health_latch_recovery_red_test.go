package analytics

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

var errHealthLatchReconcile = errors.New("reconcile failed")

func newHealthLatchRecoveryRuntime(t *testing.T) (*IngestRuntime, *recordingIngestHistoryAuthorityV1, IngestHistoryGenerationV1) {
	t.Helper()
	generation := authorityGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	if err := history.ScheduleRecovery(context.Background(), generation); err != nil {
		t.Fatal(err)
	}
	runtime := &IngestRuntime{
		history:           history,
		historyGeneration: generation,
		brokerHistorySnapshot: func(context.Context) (IngestBrokerHistorySnapshotV1, error) {
			return IngestBrokerHistorySnapshotV1{
				Generation: generation, ConsumerAckFloor: 1, StreamAckFloor: 41,
			}, nil
		},
	}
	return runtime, history, generation
}

func TestIngestRuntimeHistoryRecoveryReleasesAcknowledgedRecoveryLatch(t *testing.T) {
	t.Parallel()
	var healthyCalls atomic.Int32
	runtime, _, _ := newHealthLatchRecoveryRuntime(t)
	runtime.SetHealthyHandler(func() { healthyCalls.Add(1) })
	runtime.reportHealthy(IngestBatchResult{Fetched: 1, Naked: 1}, nil)

	recovered, err := runtime.RunScheduledHistoryRecovery(context.Background())
	if err != nil || !recovered {
		t.Fatalf("scheduled recovery = (%t, %v), want success", recovered, err)
	}
	runtime.reportHealthy(IngestBatchResult{}, ErrNoIngestMessages)
	runtime.reportHealthy(IngestBatchResult{}, ErrNoIngestMessages)
	if got := healthyCalls.Load(); got != 1 {
		t.Fatalf("healthy calls after recovered empty fetches = %d, want exactly 1", got)
	}
}

func TestIngestRuntimeHistoryRecoveryFailureKeepsAcknowledgedRecoveryLatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure func(*IngestRuntime, *recordingIngestHistoryAuthorityV1, IngestHistoryGenerationV1)
		wantErr   error
	}{
		{
			name: "fetch error after successful recovery",
			configure: func(_ *IngestRuntime, _ *recordingIngestHistoryAuthorityV1, _ IngestHistoryGenerationV1) {
			},
		},
		{
			name: "reconcile failure",
			configure: func(_ *IngestRuntime, history *recordingIngestHistoryAuthorityV1, _ IngestHistoryGenerationV1) {
				history.reconcileErr = errHealthLatchReconcile
			},
			wantErr: errHealthLatchReconcile,
		},
		{
			name: "generation mismatch",
			configure: func(runtime *IngestRuntime, _ *recordingIngestHistoryAuthorityV1, generation IngestHistoryGenerationV1) {
				changed := generation
				changed.ConsumerCreatedUnixNano++
				runtime.brokerHistorySnapshot = func(context.Context) (IngestBrokerHistorySnapshotV1, error) {
					return IngestBrokerHistorySnapshotV1{Generation: changed, ConsumerAckFloor: 1, StreamAckFloor: 41}, nil
				}
			},
			wantErr: ErrIngestHistoryGenerationChanged,
		},
		{
			name: "unclaimed recovery",
			configure: func(_ *IngestRuntime, history *recordingIngestHistoryAuthorityV1, _ IngestHistoryGenerationV1) {
				history.recoveryScheduled = false
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var healthyCalls atomic.Int32
			runtime, history, generation := newHealthLatchRecoveryRuntime(t)
			test.configure(runtime, history, generation)
			runtime.SetHealthyHandler(func() { healthyCalls.Add(1) })
			runtime.reportHealthy(IngestBatchResult{Fetched: 1, Naked: 1}, nil)

			recovered, err := runtime.RunScheduledHistoryRecovery(context.Background())
			if test.name == "fetch error after successful recovery" {
				if err != nil || !recovered {
					t.Fatalf("scheduled recovery = (%t, %v), want success", recovered, err)
				}
				runtime.reportHealthy(IngestBatchResult{}, errors.New("fetch failed"))
			} else if test.wantErr != nil {
				if recovered || !errors.Is(err, test.wantErr) {
					t.Fatalf("scheduled recovery = (%t, %v), want error %v", recovered, err, test.wantErr)
				}
			} else if err != nil || recovered {
				t.Fatalf("scheduled recovery = (%t, %v), want unclaimed", recovered, err)
			}
			runtime.reportHealthy(IngestBatchResult{}, ErrNoIngestMessages)
			if got := healthyCalls.Load(); got != 0 {
				t.Fatalf("healthy calls after unsuccessful recovery = %d, want 0", got)
			}
		})
	}
}

func TestIngestRuntimeTimedOutHistoryRecoveryKeepsAcknowledgedRecoveryLatch(t *testing.T) {
	t.Parallel()
	var healthyCalls atomic.Int32
	runtime, _, _ := newHealthLatchRecoveryRuntime(t)
	runtime.operationTimeout = 5 * time.Millisecond
	runtime.brokerHistorySnapshot = func(ctx context.Context) (IngestBrokerHistorySnapshotV1, error) {
		<-ctx.Done()
		return IngestBrokerHistorySnapshotV1{}, ctx.Err()
	}
	runtime.SetHealthyHandler(func() { healthyCalls.Add(1) })
	runtime.reportHealthy(IngestBatchResult{Fetched: 1, Naked: 1}, nil)

	recovered, err := runtime.RunScheduledHistoryRecovery(context.Background())
	if recovered || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("scheduled recovery = (%t, %v), want deadline exceeded", recovered, err)
	}
	runtime.reportHealthy(IngestBatchResult{}, ErrNoIngestMessages)
	if got := healthyCalls.Load(); got != 0 {
		t.Fatalf("healthy calls after timed-out recovery = %d, want 0", got)
	}
}

func TestIngestRuntimeFullyAcknowledgedBatchStillReportsHealthy(t *testing.T) {
	t.Parallel()
	var healthyCalls atomic.Int32
	runtime := &IngestRuntime{}
	runtime.SetHealthyHandler(func() { healthyCalls.Add(1) })
	runtime.reportHealthy(IngestBatchResult{Acknowledged: 1}, nil)
	if got := healthyCalls.Load(); got != 1 {
		t.Fatalf("healthy calls after fully acknowledged batch = %d, want 1", got)
	}
}
