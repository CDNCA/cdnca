package telemetryclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

type flushResponse struct {
	result eventspool.PublishResult
	err    error
}

type scriptedSpool struct {
	responses  chan flushResponse
	mu         sync.Mutex
	stats      eventspool.Stats
	statsBlock <-chan struct{}
}

func (s *scriptedSpool) Flush(ctx context.Context, _ eventspool.Publisher, _ int) (eventspool.PublishResult, error) {
	select {
	case response := <-s.responses:
		return response.result, response.err
	case <-ctx.Done():
		return eventspool.PublishResult{}, ctx.Err()
	}
}

func (s *scriptedSpool) Stats() (eventspool.Stats, error) {
	if s.statsBlock != nil {
		<-s.statsBlock
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats, nil
}

type unusedPublisher struct{}

func (unusedPublisher) Publish(context.Context, []eventspool.Publication) (eventspool.PublishAck, error) {
	return eventspool.PublishAck{}, errors.New("unexpected publish")
}

func TestWorkerReportsDegradedRecoveryAndCancelsPromptly(t *testing.T) {
	spool := &scriptedSpool{responses: make(chan flushResponse, 2)}
	worker, err := NewWorker(WorkerConfig{
		MaximumEvents: 10, EmptyInterval: time.Millisecond,
		InitialBackoff: time.Millisecond, MaximumBackoff: 10 * time.Millisecond,
	}, spool, unusedPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	worker.jitter = func(time.Duration) time.Duration { return 5 * time.Millisecond }
	spool.responses <- flushResponse{
		result: eventspool.PublishResult{Published: 1, LastSequence: 7},
		err:    ErrBackpressure,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	waitWorkerSnapshot(t, worker, func(snapshot WorkerSnapshot) bool {
		return snapshot.Running && snapshot.Degraded && snapshot.LastErrorCode == "TELEMETRY_BACKPRESSURE" && snapshot.AcceptedSequence == 7
	})
	spool.responses <- flushResponse{}
	waitWorkerSnapshot(t, worker, func(snapshot WorkerSnapshot) bool {
		return snapshot.Running && !snapshot.Degraded && snapshot.LastErrorCode == "" && snapshot.AcceptedSequence == 7
	})
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not honor cancellation")
	}
	if worker.Snapshot().Running {
		t.Fatal("worker remained running after cancellation")
	}
}

func TestDurableCursorReadsFsyncedSpoolStatsEveryHandshake(t *testing.T) {
	spool := &scriptedSpool{responses: make(chan flushResponse), stats: eventspool.Stats{AckedSequence: 41}}
	cursor := NewDurableCursor(spool)
	sequence, err := cursor.AcknowledgedSequence(context.Background())
	if err != nil || sequence != 41 {
		t.Fatalf("AcknowledgedSequence() = %d, %v", sequence, err)
	}
	spool.mu.Lock()
	spool.stats.AckedSequence = 42
	spool.mu.Unlock()
	sequence, err = cursor.AcknowledgedSequence(context.Background())
	if err != nil || sequence != 42 {
		t.Fatalf("second AcknowledgedSequence() = %d, %v", sequence, err)
	}
}

func TestDurableCursorCancellationBoundsShutdown(t *testing.T) {
	release := make(chan struct{})
	spool := &scriptedSpool{responses: make(chan flushResponse), statsBlock: release}
	cursor := NewDurableCursor(spool)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := cursor.AcknowledgedSequence(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcknowledgedSequence() error = %v", err)
	}
	close(release)
}

func waitWorkerSnapshot(t *testing.T, worker *Worker, condition func(WorkerSnapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition(worker.Snapshot()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for worker snapshot: %+v", worker.Snapshot())
}
