package approvalcenter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

type fakeMarker struct {
	calls chan struct{}
	err   error
}

func (f *fakeMarker) MarkStaleExecuting(context.Context) (int, error) {
	f.calls <- struct{}{}
	return 1, f.err
}

// The recovery runs once at start and then on every tick, keeps going after an
// error, and stops with the context.
func TestRunRecoveryRunsAtStartAndEveryTick(t *testing.T) {
	marker := &fakeMarker{calls: make(chan struct{}, 8), err: errors.New("db down")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunRecovery(ctx, marker, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	for pass := 0; pass < 3; pass++ {
		select {
		case <-marker.calls:
		case <-time.After(2 * time.Second):
			t.Fatalf("recovery pass %d did not run", pass)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not stop with the context")
	}
}

// A first pass at start must not wait for the interval.
func TestRunRecoveryFirstPassIsImmediate(t *testing.T) {
	marker := &fakeMarker{calls: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunRecovery(ctx, marker, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	select {
	case <-marker.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("no recovery pass at start")
	}
	if RecoveryInterval != time.Minute || StaleExecuting != 10*time.Minute {
		t.Fatalf("interval=%s stale=%s, want 1m/10m", RecoveryInterval, StaleExecuting)
	}
}
