package telemetryclient

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// permanentTelemetrySpool rejects the first `rejections` flushes permanently
// (as the gateway answers a batch it refuses), then publishes.
type permanentTelemetrySpool struct {
	rejections int32
	flushes    atomic.Int32
}

func (s *permanentTelemetrySpool) Flush(context.Context, eventspool.Publisher, int) (eventspool.PublishResult, error) {
	if s.flushes.Add(1) <= s.rejections {
		return eventspool.PublishResult{}, ErrPermanentProtocol
	}
	return eventspool.PublishResult{Published: 1, PublishedMessages: 1, LastSequence: 7}, nil
}

func (*permanentTelemetrySpool) Stats() (eventspool.Stats, error) { return eventspool.Stats{}, nil }

// N11: a permanent rejection ended the worker and, through the pipeline,
// the tail of every source. It is now retried (degraded, with its code)
// until the batch goes.
func TestWorkerRetriesPermanentProtocolErrorUntilAccepted(t *testing.T) {
	spool := &permanentTelemetrySpool{rejections: 3}
	worker, err := NewWorker(WorkerConfig{
		MaximumEvents: 1, EmptyInterval: time.Millisecond,
		InitialBackoff: time.Millisecond, MaximumBackoff: 2 * time.Millisecond,
	}, spool, unusedPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	sawDegraded := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case runErr := <-done:
			t.Fatalf("Run() stopped on a permanent rejection: %v", runErr)
		default:
		}
		snapshot := worker.Snapshot()
		if snapshot.Degraded && snapshot.LastErrorCode == "TELEMETRY_PROTOCOL_REJECTED" {
			sawDegraded = true
		}
		if spool.flushes.Load() > 4 && !snapshot.Degraded && snapshot.AcceptedSequence == 7 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	snapshot := worker.Snapshot()
	if !sawDegraded || !snapshot.Running || snapshot.Degraded || snapshot.AcceptedSequence != 7 || spool.flushes.Load() <= 3 {
		t.Fatalf("degraded seen %v, state %+v after %d flushes", sawDegraded, snapshot, spool.flushes.Load())
	}
	cancel()
	if runErr := <-done; !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Run() error = %v", runErr)
	}
}

var _ Spool = (*permanentTelemetrySpool)(nil)
