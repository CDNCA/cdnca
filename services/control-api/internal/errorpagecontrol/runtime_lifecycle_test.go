package errorpagecontrol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuntimeHandlerOwnsPublicationAndReconcileLifecycle(t *testing.T) {
	dependencies := runtimeFactoryDependencies(t, "runtime-lifecycle")
	runtime, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Handler() == nil || runtime.service == nil || runtime.service.pool != dependencies.Pool ||
		runtime.worker != runtime.service || isNilDependency(runtime.service.auditor) ||
		isNilDependency(runtime.service.content) || isNilDependency(runtime.service.scanner) ||
		isNilDependency(runtime.service.limits) {
		t.Fatalf("runtime handler=%T service=%T worker=%T", runtime.Handler(), runtime.service, runtime.worker)
	}
	if _, ok := any(runtime.service).(interface {
		PublicationSnapshot(context.Context, Actor) (PublicationSnapshot, error)
	}); !ok {
		t.Fatalf("runtime service %T has no PostgreSQL publication capability", runtime.service)
	}
}

func TestRuntimeHandlerRejectsInvalidWorkerReadiness(t *testing.T) {
	valid := runtimeFactoryDependencies(t, "runtime-readiness")
	tests := map[string]func(*RuntimeConfig, *RuntimeDependencies){
		"negative batch": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.ReconcileBatchSize = -1
		},
		"negative reconcile timeout": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.ReconcileTimeout = -time.Second
		},
		"negative idle poll": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.WorkerIdlePoll = -time.Second
		},
		"negative error backoff": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.WorkerErrorBackoff = -time.Second
		},
		"panicking object capabilities": func(_ *RuntimeConfig, dependencies *RuntimeDependencies) {
			dependencies.ContentStore = panickingRuntimeContentStore{ContentStore: dependencies.ContentStore}
		},
		"panicking scanner readiness": func(_ *RuntimeConfig, dependencies *RuntimeDependencies) {
			dependencies.Scanner = panickingRuntimeScanner{}
		},
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			config := RuntimeConfig{Enabled: true}
			dependencies := valid
			invalidate(&config, &dependencies)
			runtime, err := NewRuntimeHandler(config, dependencies)
			if runtime != nil || !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidStore", runtime, err)
			}
		})
	}
}

type runtimeReconcilerResult struct {
	count int
	err   error
}

type runtimeReconcilerStub struct {
	calls   chan int
	results chan runtimeReconcilerResult
}

func (reconciler *runtimeReconcilerStub) ReconcileAssets(ctx context.Context, _ int) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case result := <-reconciler.results:
		select {
		case reconciler.calls <- result.count:
		default:
		}
		return result.count, result.err
	}
}

func TestRuntimeWorkerRetriesRejectsConcurrentRunAndCloses(t *testing.T) {
	reconciler := &runtimeReconcilerStub{
		calls:   make(chan int, 3),
		results: make(chan runtimeReconcilerResult, 3),
	}
	reconciler.results <- runtimeReconcilerResult{err: errors.New("SQLSTATE 57P01 bucket=/secret/path")}
	reconciler.results <- runtimeReconcilerResult{count: 1}
	runtime := newRuntime(http.NotFoundHandler(), nil, reconciler, 10, time.Millisecond, time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()
	for range 2 {
		select {
		case <-reconciler.calls:
		case <-time.After(time.Second):
			t.Fatal("runtime worker did not retry")
		}
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeAlreadyRunning) {
		t.Fatalf("concurrent Run() error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Run() after Close error = %v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready() after Close error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestRuntimeReadinessTracksReconcileResultsAndParentExit(t *testing.T) {
	reconciler := &runtimeReconcilerStub{
		calls:   make(chan int, 5),
		results: make(chan runtimeReconcilerResult),
	}
	runtime := newRuntime(http.NotFoundHandler(), nil, reconciler, 10, time.Millisecond, time.Millisecond)
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready() before Run error = %v, want ErrRuntimeNotReady", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitErrorPageRuntimeRunning(t, runtime)
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready() before first reconcile error = %v, want ErrRuntimeNotReady", err)
	}

	results := []struct {
		result    runtimeReconcilerResult
		wantReady bool
	}{
		{result: runtimeReconcilerResult{count: 0}, wantReady: true},
		{result: runtimeReconcilerResult{err: errors.New("SQLSTATE 57P01 storage=/secret/path")}},
		{result: runtimeReconcilerResult{count: 2}, wantReady: true},
		{result: runtimeReconcilerResult{count: -1}},
		{result: runtimeReconcilerResult{count: 0}, wantReady: true},
	}
	for index, test := range results {
		reconciler.results <- test.result
		select {
		case <-reconciler.calls:
		case <-time.After(time.Second):
			t.Fatalf("reconcile result %d was not observed", index)
		}
		err := waitErrorPageRuntimeReadiness(t, runtime, test.wantReady)
		if !test.wantReady {
			for _, detail := range []string{"worker", "SQLSTATE", "57P01", "storage", "/secret/path"} {
				if strings.Contains(err.Error(), detail) {
					t.Fatalf("Ready() leaked %q: %v", detail, err)
				}
			}
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() after parent cancellation error = %v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready() after Run exit error = %v, want ErrRuntimeNotReady", err)
	}
}

func TestRuntimeFirstSuccessfulReconcileBecomesReady(t *testing.T) {
	tests := []struct {
		name  string
		count int
	}{
		{name: "zero", count: 0},
		{name: "positive", count: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reconciler := &runtimeReconcilerStub{
				calls:   make(chan int, 1),
				results: make(chan runtimeReconcilerResult, 1),
			}
			reconciler.results <- runtimeReconcilerResult{count: test.count}
			runtime := newRuntime(http.NotFoundHandler(), nil, reconciler, 10, time.Hour, time.Hour)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- runtime.Run(ctx) }()
			select {
			case <-reconciler.calls:
			case <-time.After(time.Second):
				t.Fatal("runtime worker did not reconcile")
			}
			waitErrorPageRuntimeReadiness(t, runtime, true)
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("Run() error = %v", err)
			}
		})
	}
}

func TestRuntimeReconcileDeadlineExpiresReadiness(t *testing.T) {
	reconciler := &runtimeReconcilerStub{
		calls:   make(chan int, 1),
		results: make(chan runtimeReconcilerResult, 1),
	}
	reconciler.results <- runtimeReconcilerResult{}
	runtime := newRuntime(http.NotFoundHandler(), nil, reconciler, 10, 50*time.Millisecond, time.Hour)
	runtime.timeout = 20 * time.Millisecond

	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()
	select {
	case <-reconciler.calls:
	case <-time.After(time.Second):
		t.Fatal("runtime worker did not complete its first reconcile")
	}
	waitErrorPageRuntimeReadiness(t, runtime, true)
	waitErrorPageRuntimeReadiness(t, runtime, false)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRuntimeWorkerPanicStopsFailClosed(t *testing.T) {
	runtime := newRuntime(http.NotFoundHandler(), nil, panicRuntimeReconciler{}, 10,
		time.Millisecond, time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Run() error = %v, want ErrUnavailable", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not stop after worker panic")
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready() after worker panic = %v, want ErrRuntimeNotReady", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() after worker panic = %v", err)
	}
}

func TestRuntimeConcurrentCloseRemainsNotReady(t *testing.T) {
	reconciler := &runtimeReconcilerStub{
		calls:   make(chan int, 1),
		results: make(chan runtimeReconcilerResult, 1),
	}
	reconciler.results <- runtimeReconcilerResult{count: 0}
	runtime := newRuntime(http.NotFoundHandler(), nil, reconciler, 10, time.Millisecond, time.Millisecond)
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()
	select {
	case <-reconciler.calls:
	case <-time.After(time.Second):
		t.Fatal("runtime worker did not reconcile")
	}
	waitErrorPageRuntimeReadiness(t, runtime, true)

	closeResults := make(chan error, 8)
	for range 8 {
		go func() { closeResults <- runtime.Close() }()
	}
	for range 8 {
		if err := <-closeResults; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready() after concurrent Close error = %v, want ErrRuntimeNotReady", err)
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Run() after concurrent Close error = %v, want ErrRuntimeClosed", err)
	}
}

func TestDisabledRuntimeNeverReportsWorkerReady(t *testing.T) {
	runtime, err := NewRuntimeHandler(RuntimeConfig{}, RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.worker != nil {
		t.Fatalf("disabled runtime worker = %T, want nil", runtime.worker)
	}
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://control.test/", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled runtime status = %d, want %d", response.Code, http.StatusNotFound)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitErrorPageRuntimeRunning(t, runtime)
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("disabled Ready() error = %v, want ErrRuntimeNotReady", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("disabled Run() error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("disabled Close() error = %v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("disabled Ready() after Close error = %v, want ErrRuntimeNotReady", err)
	}
}

func waitErrorPageRuntimeRunning(t *testing.T, runtime *Runtime) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		runtime.mu.Lock()
		running := runtime.running
		runtime.mu.Unlock()
		if running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("runtime did not start")
}

func waitErrorPageRuntimeReadiness(t *testing.T, runtime *Runtime, wantReady bool) error {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err := runtime.Ready()
		if (err == nil) == wantReady {
			if err != nil && !errors.Is(err, ErrRuntimeNotReady) {
				t.Fatalf("Ready() error = %v, want ErrRuntimeNotReady", err)
			}
			return err
		}
		time.Sleep(time.Millisecond)
	}
	err := runtime.Ready()
	t.Fatalf("Ready() error = %v, want ready=%t", err, wantReady)
	return err
}

type panickingRuntimeContentStore struct{ ContentStore }

func (panickingRuntimeContentStore) Capabilities() ObjectStoreCapabilities { panic("storage secret") }

type panickingRuntimeScanner struct{}

func (panickingRuntimeScanner) Name() string { panic("scanner secret") }
func (panickingRuntimeScanner) Scan(context.Context, ScanInput) error {
	return nil
}

type panicRuntimeReconciler struct{}

func (panicRuntimeReconciler) ReconcileAssets(context.Context, int) (int, error) {
	panic("worker dependency detail")
}
