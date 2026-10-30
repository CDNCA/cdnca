package identityverificationhttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
)

type runtimePublisherStub struct {
	configured      bool
	configuredCheck func() bool
	publish         func(context.Context, identityverification.SettlementCommitRequest) (identityverification.SettlementCommitResult, error)
}

func (publisher runtimePublisherStub) Configured() bool {
	if publisher.configuredCheck != nil {
		return publisher.configuredCheck()
	}
	return publisher.configured
}

func (publisher runtimePublisherStub) Publish(ctx context.Context,
	request identityverification.SettlementCommitRequest,
) (identityverification.SettlementCommitResult, error) {
	if publisher.publish == nil {
		return identityverification.SettlementCommitResult{
			Outcome: identityverification.SettlementCommitSucceeded,
		}, nil
	}
	return publisher.publish(ctx, request)
}

type runtimeProcessorStub struct {
	mu       sync.Mutex
	calls    int
	results  []runtimeProcessorResult
	observed chan int
}

type runtimeProcessorResult struct {
	processed bool
	err       error
}

func (processor *runtimeProcessorStub) RunOnce(ctx context.Context) (bool, error) {
	processor.mu.Lock()
	processor.calls++
	call := processor.calls
	var result runtimeProcessorResult
	if len(processor.results) > 0 {
		result = processor.results[0]
		processor.results = processor.results[1:]
	}
	processor.mu.Unlock()
	select {
	case processor.observed <- call:
	default:
	}
	if result.processed || result.err != nil {
		return result.processed, result.err
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(time.Millisecond):
		return false, nil
	}
}

func (processor *runtimeProcessorStub) callCount() int {
	processor.mu.Lock()
	defer processor.mu.Unlock()
	return processor.calls
}

func TestRuntimeRejectsMissingPublisherClockAndWorkerConfiguration(t *testing.T) {
	validConfig := RuntimeConfig{Enabled: true,
		Service: ServiceConfig{CursorKey: bytes.Repeat([]byte{0x41}, 32)}}
	valid := runtimeUnitDependencies(t)
	var typedNilPublisher *runtimePublisherStub
	tests := map[string]func(*RuntimeConfig, *RuntimeDependencies){
		"nil publisher": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.SettlementPublisher = nil
		},
		"typed nil publisher": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.SettlementPublisher = typedNilPublisher
		},
		"unconfigured publisher": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.SettlementPublisher = runtimePublisherStub{}
		},
		"panicking publisher": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.SettlementPublisher = runtimePublisherStub{configuredCheck: func() bool { panic("secret") }}
		},
		"nil clock": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Clock = nil
		},
		"zero clock": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Clock = func() time.Time { return time.Time{} }
		},
		"panicking clock": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Clock = func() time.Time { panic("secret") }
		},
		"negative idle poll": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.WorkerIdlePoll = -time.Second
		},
		"negative error backoff": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.WorkerErrorBackoff = -time.Second
		},
		"invalid settlement lease": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.Settlement.LeaseDuration = -time.Second
		},
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			config, dependencies := validConfig, valid
			invalidate(&config, &dependencies)
			runtime, err := NewRuntime(config, dependencies)
			if runtime != nil || !errors.Is(err, ErrInvalidService) {
				t.Fatalf("NewRuntime() = (%T,%v), want nil ErrInvalidService", runtime, err)
			}
		})
	}
}

func TestRuntimeWorkerRecoversRestartsAndCloses(t *testing.T) {
	processor := &runtimeProcessorStub{observed: make(chan int, 8), results: []runtimeProcessorResult{
		{processed: true, err: errors.New("publisher unavailable")},
		{processed: true},
	}}
	runtime := newRuntime(http.NotFoundHandler(), processor, time.Millisecond, time.Millisecond)

	firstCtx, cancelFirst := context.WithCancel(t.Context())
	firstDone := make(chan error, 1)
	go func() { firstDone <- runtime.Run(firstCtx) }()
	waitRuntimeCall(t, processor.observed, 2)
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeAlreadyRunning) {
		t.Fatalf("concurrent Run() error = %v", err)
	}
	cancelFirst()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Run() error = %v", err)
	}

	nextCall := processor.callCount() + 1
	secondDone := make(chan error, 1)
	go func() { secondDone <- runtime.Run(t.Context()) }()
	waitRuntimeCall(t, processor.observed, nextCall)
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Run(after Close) error = %v", err)
	}
}

func TestRuntimeReadinessTracksWorkerFailureRecoveryAndRestart(t *testing.T) {
	attempts := make(chan chan runtimeProcessorResult)
	processor := settlementProcessorFunc(func(ctx context.Context) (bool, error) {
		result := make(chan runtimeProcessorResult, 1)
		select {
		case attempts <- result:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		select {
		case value := <-result:
			return value.processed, value.err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	})
	runtime := newRuntime(http.NotFoundHandler(), processor, time.Hour, time.Millisecond)
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready(before Run) error = %v, want ErrRuntimeNotReady", err)
	}

	firstCtx, cancelFirst := context.WithCancel(t.Context())
	firstDone := make(chan error, 1)
	go func() { firstDone <- runtime.Run(firstCtx) }()
	first := <-attempts
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready(before first successful poll) error = %v, want ErrRuntimeNotReady", err)
	}
	first <- runtimeProcessorResult{processed: true}
	second := <-attempts
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready(after successful poll) error = %v", err)
	}
	second <- runtimeProcessorResult{processed: true, err: errors.New("publisher unavailable")}
	third := <-attempts
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready(after worker failure) error = %v, want ErrRuntimeNotReady", err)
	}
	third <- runtimeProcessorResult{processed: true}
	<-attempts
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready(after worker recovery) error = %v", err)
	}
	cancelFirst()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready(after Run exit) error = %v, want ErrRuntimeNotReady", err)
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- runtime.Run(t.Context()) }()
	restarted := <-attempts
	restarted <- runtimeProcessorResult{processed: true}
	<-attempts
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready(after restart) error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready(after Close) error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestConcurrentCloseWaitsForWorkerExit(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	processor := settlementProcessorFunc(func(ctx context.Context) (bool, error) {
		close(entered)
		<-release
		return false, ctx.Err()
	})
	runtime := newRuntime(http.NotFoundHandler(), processor, time.Millisecond, time.Millisecond)
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()
	<-entered

	closeResults := make(chan error, 2)
	go func() { closeResults <- runtime.Close() }()
	waitRuntimeClosed(t, runtime)
	go func() { closeResults <- runtime.Close() }()

	select {
	case err := <-closeResults:
		t.Fatalf("Close returned before worker exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	for range 2 {
		if err := <-closeResults; err != nil {
			t.Fatalf("Close error = %v", err)
		}
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run error = %v", err)
	}
}

type settlementProcessorFunc func(context.Context) (bool, error)

func (run settlementProcessorFunc) RunOnce(ctx context.Context) (bool, error) {
	return run(ctx)
}

func TestDisabledRuntimeDoesNotTouchPublisherOrClockAndCloses(t *testing.T) {
	dependencies := RuntimeDependencies{
		SettlementPublisher: runtimePublisherStub{configuredCheck: func() bool {
			t.Fatal("disabled runtime touched publisher")
			return false
		}},
		Clock: func() time.Time {
			t.Fatal("disabled runtime touched clock")
			return time.Time{}
		},
	}
	runtime, err := NewRuntime(RuntimeConfig{}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()
	waitRuntimeRunning(t, runtime)
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("disabled Ready() error = %v, want ErrRuntimeNotReady", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func waitRuntimeRunning(t *testing.T, runtime *Runtime) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		runtime.mu.Lock()
		running := runtime.running
		runtime.mu.Unlock()
		if running {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("runtime did not start")
		case <-time.After(time.Millisecond):
		}
	}
}

func waitRuntimeClosed(t *testing.T, runtime *Runtime) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		runtime.mu.Lock()
		closed := runtime.closed
		runtime.mu.Unlock()
		if closed {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("runtime did not enter closed state")
		case <-time.After(time.Millisecond):
		}
	}
}

func waitRuntimeCall(t *testing.T, calls <-chan int, minimum int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case call := <-calls:
			if call >= minimum {
				return
			}
		case <-deadline.C:
			t.Fatalf("runtime did not reach call %d", minimum)
		}
	}
}
