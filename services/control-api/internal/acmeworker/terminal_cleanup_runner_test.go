package acmeworker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type terminalCleanupProcessor37 struct {
	mu      sync.Mutex
	results []struct {
		found bool
		err   error
	}
	calls   int
	panicAt int
	called  chan struct{}
}

func (processor *terminalCleanupProcessor37) CleanupTerminalChallengeOnce(context.Context) (bool, error) {
	processor.mu.Lock()
	defer processor.mu.Unlock()
	processor.calls++
	if processor.called != nil && processor.calls == 1 {
		close(processor.called)
	}
	if processor.panicAt == processor.calls {
		panic("terminal cleanup panic")
	}
	index := processor.calls - 1
	if index >= len(processor.results) {
		return false, nil
	}
	return processor.results[index].found, processor.results[index].err
}

func TestTerminalCleanupRunnerRunOnceBoundsBatch37(t *testing.T) {
	processor := &terminalCleanupProcessor37{results: []struct {
		found bool
		err   error
	}{{found: true}, {found: true}, {found: true}, {found: true}}}
	config := DefaultTerminalCleanupRunnerConfig()
	config.BatchSize = 3
	runner, err := newTerminalCleanupRunner(processor, config, waitForTerminalCleanupContext)
	if err != nil {
		t.Fatal(err)
	}
	processed, err := runner.RunOnce(t.Context())
	if err != nil || processed != 3 || processor.calls != 3 {
		t.Fatalf("RunOnce()=(%d,%v) calls=%d", processed, err, processor.calls)
	}
	processed, err = runner.RunOnce(t.Context())
	if err != nil || processed != 1 || processor.calls != 5 {
		t.Fatalf("second RunOnce()=(%d,%v) calls=%d", processed, err, processor.calls)
	}
}

func TestTerminalCleanupRunnerBackoffCapsRecoversAndPolls37(t *testing.T) {
	temporary := failure(CodeOperationStoreFailed, nil)
	processor := &terminalCleanupProcessor37{results: []struct {
		found bool
		err   error
	}{
		{err: temporary}, {err: temporary}, {err: temporary},
		{found: true}, {found: false},
	}}
	config := DefaultTerminalCleanupRunnerConfig()
	config.BatchSize = 4
	config.PollInterval = 20 * time.Millisecond
	config.ErrorBackoffMin = 5 * time.Millisecond
	config.ErrorBackoffMax = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	runner, err := newTerminalCleanupRunner(processor, config, func(waitCtx context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		if len(waits) == 4 {
			cancel()
			return waitCtx.Err()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error=%v", err)
	}
	want := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}
	if len(waits) != len(want) {
		t.Fatalf("waits=%v", waits)
	}
	for index := range want {
		if waits[index] != want[index] {
			t.Fatalf("waits=%v want=%v", waits, want)
		}
	}
	if processor.calls != 5 {
		t.Fatalf("processor calls=%d", processor.calls)
	}
}

func TestTerminalCleanupRunnerCancelInterruptsWaitAndReadiness37(t *testing.T) {
	processor := &terminalCleanupProcessor37{called: make(chan struct{})}
	config := DefaultTerminalCleanupRunnerConfig()
	config.PollInterval = time.Hour
	runner, err := newTerminalCleanupRunner(processor, config, waitForTerminalCleanupContext)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-processor.called:
	case <-time.After(time.Second):
		t.Fatal("runner did not poll")
	}
	if err := runner.Ready(); err != nil {
		t.Fatalf("running readiness error=%v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt poll timer")
	}
	if runner.Ready() == nil {
		t.Fatal("stopped runner remained ready")
	}
}

func TestTerminalCleanupRunnerRejectsConcurrentRunAndPropagatesPanic37(t *testing.T) {
	processor := &terminalCleanupProcessor37{called: make(chan struct{}), panicAt: 2}
	config := DefaultTerminalCleanupRunnerConfig()
	config.PollInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := make(chan struct{})
	release := make(chan struct{})
	runner, err := newTerminalCleanupRunner(processor, config, func(waitCtx context.Context, _ time.Duration) error {
		close(waiting)
		select {
		case <-release:
			return nil
		case <-waitCtx.Done():
			return waitCtx.Err()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	<-waiting
	if err := runner.Run(ctx); err == nil {
		t.Fatal("concurrent Run unexpectedly succeeded")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("first Run error=%v", err)
	}

	panicProcessor := &terminalCleanupProcessor37{panicAt: 1}
	panicRunner, err := newTerminalCleanupRunner(panicProcessor, config, waitForTerminalCleanupContext)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recovered := recover(); recovered != "terminal cleanup panic" {
			t.Fatalf("recovered=%v", recovered)
		}
	}()
	_, _ = panicRunner.RunOnce(t.Context())
}

func TestTerminalCleanupRunnerValidatesConfigurationAndWorker37(t *testing.T) {
	processor := &terminalCleanupProcessor37{}
	valid := DefaultTerminalCleanupRunnerConfig()
	tests := []TerminalCleanupRunnerConfig{
		{PollInterval: valid.PollInterval, ErrorBackoffMin: valid.ErrorBackoffMin, ErrorBackoffMax: valid.ErrorBackoffMax},
		{BatchSize: valid.BatchSize, ErrorBackoffMin: valid.ErrorBackoffMin, ErrorBackoffMax: valid.ErrorBackoffMax},
		{BatchSize: valid.BatchSize, PollInterval: valid.PollInterval, ErrorBackoffMax: valid.ErrorBackoffMax},
		{BatchSize: valid.BatchSize, PollInterval: valid.PollInterval, ErrorBackoffMin: valid.ErrorBackoffMin},
	}
	for index, config := range tests {
		if _, err := newTerminalCleanupRunner(processor, config, waitForTerminalCleanupContext); ErrorCodeOf(err) != CodeInvalidInput {
			t.Fatalf("invalid config %d error=%v", index, err)
		}
	}
	if _, err := newTerminalCleanupRunner(nil, valid, waitForTerminalCleanupContext); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("nil processor error=%v", err)
	}
	if _, err := newTerminalCleanupRunner(processor, valid, nil); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("nil wait error=%v", err)
	}
	unsupported := &Worker{config: DefaultConfig("https://acme.example/directory"), deps: Dependencies{
		Operations: &struct{ OperationStore }{},
	}}
	if _, err := NewTerminalCleanupRunner(unsupported, valid); ErrorCodeOf(err) != CodeChallengeUnavailable {
		t.Fatalf("unsupported worker error=%v", err)
	}
}
