package edgeautopublish

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type runtimeWorkerStub struct {
	mu      sync.Mutex
	results []runtimeResult
	calls   int
}

type runtimeReconcilerStub struct {
	mu      sync.Mutex
	results []runtimeResult
	calls   int
}

type runtimeResult struct {
	worked bool
	err    error
}

func (stub *runtimeWorkerStub) RunOnce(context.Context) (bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls++
	if len(stub.results) == 0 {
		return false, nil
	}
	result := stub.results[0]
	stub.results = stub.results[1:]
	return result.worked, result.err
}

func (stub *runtimeReconcilerStub) ReconcileOne(context.Context) (bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls++
	if len(stub.results) == 0 {
		return false, nil
	}
	result := stub.results[0]
	stub.results = stub.results[1:]
	return result.worked, result.err
}

func (stub *runtimeWorkerStub) callCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.calls
}

func (stub *runtimeReconcilerStub) callCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.calls
}

func TestRuntimeRejectsInvalidDependenciesAndConfig(t *testing.T) {
	valid := RuntimeConfig{PollInterval: time.Second, ErrorBackoff: time.Second, OperationTimeout: time.Second}
	worker := &runtimeWorkerStub{}
	reconciler := &runtimeReconcilerStub{}

	tests := []struct {
		name       string
		worker     RuntimeWorker
		reconciler RuntimeReconciler
		config     RuntimeConfig
	}{
		{name: "nil worker", reconciler: reconciler, config: valid},
		{name: "nil reconciler", worker: worker, config: valid},
		{name: "zero poll", worker: worker, reconciler: reconciler, config: RuntimeConfig{ErrorBackoff: time.Second, OperationTimeout: time.Second}},
		{name: "zero backoff", worker: worker, reconciler: reconciler, config: RuntimeConfig{PollInterval: time.Second, OperationTimeout: time.Second}},
		{name: "zero operation timeout", worker: worker, reconciler: reconciler, config: RuntimeConfig{PollInterval: time.Second, ErrorBackoff: time.Second}},
		{name: "poll too large", worker: worker, reconciler: reconciler, config: RuntimeConfig{PollInterval: time.Hour + time.Nanosecond, ErrorBackoff: time.Second, OperationTimeout: time.Second}},
		{name: "backoff too large", worker: worker, reconciler: reconciler, config: RuntimeConfig{PollInterval: time.Second, ErrorBackoff: time.Hour + time.Nanosecond, OperationTimeout: time.Second}},
		{name: "operation timeout too large", worker: worker, reconciler: reconciler, config: RuntimeConfig{PollInterval: time.Second, ErrorBackoff: time.Second, OperationTimeout: time.Hour + time.Nanosecond}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRuntime(test.worker, test.reconciler, test.config); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewRuntime error = %v", err)
			}
		})
	}
}

func TestRuntimeDrainsWorkBeforeIdleWait(t *testing.T) {
	worker := &runtimeWorkerStub{results: []runtimeResult{{worked: true}, {worked: false}}}
	reconciler := &runtimeReconcilerStub{results: []runtimeResult{{worked: true}, {worked: false}}}
	ctx, cancel := context.WithCancel(t.Context())
	var waits []time.Duration
	runtime, err := newRuntime(worker, reconciler, RuntimeConfig{
		PollInterval: time.Second, ErrorBackoff: 2 * time.Second, OperationTimeout: time.Minute,
	}, func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		cancel()
		return context.Canceled
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if worker.callCount() != 2 || reconciler.callCount() != 2 {
		t.Fatalf("calls worker=%d reconciler=%d", worker.callCount(), reconciler.callCount())
	}
	if len(waits) != 1 || waits[0] != time.Second {
		t.Fatalf("waits = %v", waits)
	}
	if !errors.Is(runtime.Ready(), ErrRuntimeClosed) {
		t.Fatalf("Ready after parent cancellation = %v", runtime.Ready())
	}
}

func TestRuntimeAttemptsBothPathsAndRecoversReadiness(t *testing.T) {
	workerFailure := errors.New("worker store unavailable")
	reconcilerFailure := errors.New("rollout projection unavailable")
	worker := &runtimeWorkerStub{results: []runtimeResult{{err: workerFailure}, {}, {}}}
	reconciler := &runtimeReconcilerStub{results: []runtimeResult{{err: reconcilerFailure}, {}, {}}}
	ctx, cancel := context.WithCancel(t.Context())
	waits := make([]time.Duration, 0, 2)
	var runtime *Runtime
	runtime, err := newRuntime(worker, reconciler, RuntimeConfig{
		PollInterval: time.Second, ErrorBackoff: 2 * time.Second, OperationTimeout: time.Minute,
	}, func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		if len(waits) == 1 {
			if readyErr := runtime.Ready(); readyErr == nil || errors.Is(readyErr, ErrRuntimeNotReady) {
				t.Fatalf("Ready after failed cycle = %v", readyErr)
			}
			return nil
		}
		if readyErr := runtime.Ready(); readyErr != nil {
			t.Fatalf("Ready after recovery = %v", readyErr)
		}
		cancel()
		return context.Canceled
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if worker.callCount() != 2 || reconciler.callCount() != 2 {
		t.Fatalf("calls worker=%d reconciler=%d", worker.callCount(), reconciler.callCount())
	}
	if len(waits) != 2 || waits[0] != 2*time.Second || waits[1] != time.Second {
		t.Fatalf("waits = %v", waits)
	}
}

func TestRuntimeRejectsConcurrentRunAndCloseDrains(t *testing.T) {
	worker := &runtimeWorkerStub{}
	reconciler := &runtimeReconcilerStub{}
	waiting := make(chan struct{})
	runtime, err := newRuntime(worker, reconciler, RuntimeConfig{
		PollInterval: time.Hour, ErrorBackoff: time.Second, OperationTimeout: time.Minute,
	}, func(ctx context.Context, _ time.Duration) error {
		close(waiting)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()

	<-waiting
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready while running = %v", err)
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeAlreadyRunning) {
		t.Fatalf("second Run error = %v", err)
	}
	closeCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after Close error = %v", err)
	}
	if !errors.Is(runtime.Ready(), ErrRuntimeClosed) {
		t.Fatalf("Ready after Close = %v", runtime.Ready())
	}
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
}

type blockingRuntimeWorker struct{}

func (*blockingRuntimeWorker) RunOnce(ctx context.Context) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

type contextCheckingRuntimeReconciler struct {
	mu     sync.Mutex
	calls  int
	ctxErr error
}

func (reconciler *contextCheckingRuntimeReconciler) ReconcileOne(ctx context.Context) (bool, error) {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	reconciler.calls++
	reconciler.ctxErr = ctx.Err()
	return false, reconciler.ctxErr
}

func (reconciler *contextCheckingRuntimeReconciler) result() (int, error) {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	return reconciler.calls, reconciler.ctxErr
}

func TestRuntimeBoundsEachCycleWithOperationTimeout(t *testing.T) {
	reconciler := &contextCheckingRuntimeReconciler{}
	ctx, cancel := context.WithCancel(t.Context())
	var runtime *Runtime
	runtime, err := newRuntime(&blockingRuntimeWorker{}, reconciler, RuntimeConfig{
		PollInterval: time.Second, ErrorBackoff: 2 * time.Second, OperationTimeout: 10 * time.Millisecond,
	}, func(_ context.Context, delay time.Duration) error {
		if delay != 2*time.Second {
			t.Fatalf("wait delay = %v", delay)
		}
		if readyErr := runtime.Ready(); !errors.Is(readyErr, context.DeadlineExceeded) {
			t.Fatalf("Ready after operation timeout = %v", readyErr)
		}
		cancel()
		return context.Canceled
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if calls, ctxErr := reconciler.result(); calls != 1 || ctxErr != nil {
		t.Fatalf("reconciler calls = %d, context error = %v", calls, ctxErr)
	}
}
