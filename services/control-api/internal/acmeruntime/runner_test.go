package acmeruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRunnerPollsDrainsAndBacksOff(t *testing.T) {
	databaseError := errors.New("database unavailable")
	dispatcher := &scriptedDispatchSource{results: []dispatchStep{
		{result: DispatchResult{Outcome: OutcomeIdle}},
		{err: databaseError},
		{err: databaseError},
		{result: DispatchResult{Outcome: OutcomeCompleted}},
		{result: DispatchResult{Outcome: OutcomeRetry}},
		{result: DispatchResult{Outcome: OutcomeExhausted}},
		{result: DispatchResult{Outcome: "invalid"}},
	}}
	var waits []time.Duration
	runner, err := newRunner(dispatcher, RunnerConfig{
		PollInterval: 20 * time.Millisecond, ErrorBackoffMin: 30 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond,
	}, func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Ready(); err == nil {
		t.Fatal("runner was ready before Run")
	}
	if err := runner.Run(t.Context()); err == nil || err.Error() != "ACME runtime dispatcher returned an invalid outcome" {
		t.Fatalf("Run() error = %v", err)
	}
	if err := runner.Ready(); err == nil {
		t.Fatal("runner remained ready after unexpected exit")
	}
	if want := []time.Duration{20 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond}; len(waits) != len(want) || waits[0] != want[0] || waits[1] != want[1] || waits[2] != want[2] {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
}

func TestRunnerReadyWhileActiveAndCancellationJoins(t *testing.T) {
	entered := make(chan struct{})
	dispatcher := dispatchSourceFunc(func(ctx context.Context) (DispatchResult, error) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-ctx.Done()
		return DispatchResult{}, ctx.Err()
	})
	runner, err := NewRunner(dispatcher, DefaultRunnerConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	<-entered
	if err := runner.Ready(); err != nil {
		t.Fatalf("Ready() while active = %v", err)
	}
	if err := runner.Run(ctx); err == nil || err.Error() != "ACME runtime is already running" {
		t.Fatalf("concurrent Run() error = %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not join after cancellation")
	}
	if err := runner.Ready(); err == nil {
		t.Fatal("runner remained ready after cancellation")
	}
}

func TestRunnerCancellationInterruptsIdleWait(t *testing.T) {
	runner, err := NewRunner(
		dispatchSourceFunc(func(context.Context) (DispatchResult, error) {
			return DispatchResult{Outcome: OutcomeIdle}, nil
		}),
		RunnerConfig{PollInterval: time.Hour, ErrorBackoffMin: time.Second, ErrorBackoffMax: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	for deadline := time.Now().Add(time.Second); runner.Ready() != nil && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle wait ignored cancellation")
	}
}

type dispatchStep struct {
	result DispatchResult
	err    error
}

type scriptedDispatchSource struct {
	mu      sync.Mutex
	results []dispatchStep
}

func (s *scriptedDispatchSource) DispatchOne(context.Context) (DispatchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.results) == 0 {
		return DispatchResult{Outcome: OutcomeIdle}, nil
	}
	step := s.results[0]
	s.results = s.results[1:]
	return step.result, step.err
}

type dispatchSourceFunc func(context.Context) (DispatchResult, error)

func (f dispatchSourceFunc) DispatchOne(ctx context.Context) (DispatchResult, error) {
	return f(ctx)
}
