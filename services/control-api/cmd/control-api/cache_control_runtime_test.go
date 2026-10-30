package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func TestBuildCacheControlRuntimeDisabledDoesNotRequireDependencies(t *testing.T) {
	runtime, err := buildCacheControlRuntime(cacheControlRuntimeConfig{}, cacheControlRuntimeDependencies{})
	if err != nil || runtime != nil {
		t.Fatalf("disabled cache control runtime = (%v, %v), want nil", runtime, err)
	}
}

func TestBuildCacheControlRuntimeEnabledFailsClosed(t *testing.T) {
	config := cacheControlRuntimeConfig{
		Enabled: true, CursorKey: bytes.Repeat([]byte{0x41}, 32),
		Worker: cachecontrolruntime.DefaultConfig(),
	}
	dependencies := configuredCacheControlRuntimeDependencies(t)
	tests := []struct {
		name                  string
		configure             func(*cacheControlRuntimeConfig)
		dependencies          cacheControlRuntimeDependencies
		wantConfigurationGate bool
	}{
		{name: "missing cursor key", configure: func(config *cacheControlRuntimeConfig) { config.CursorKey = nil }, dependencies: dependencies, wantConfigurationGate: true},
		{name: "missing pool", dependencies: func() cacheControlRuntimeDependencies { value := dependencies; value.Pool = nil; return value }(), wantConfigurationGate: true},
		{name: "missing NATS", dependencies: func() cacheControlRuntimeDependencies { value := dependencies; value.NATS = nil; return value }(), wantConfigurationGate: true},
		{name: "missing node leases", dependencies: func() cacheControlRuntimeDependencies { value := dependencies; value.NodeLeases = nil; return value }(), wantConfigurationGate: true},
		{name: "missing entitlement", dependencies: func() cacheControlRuntimeDependencies { value := dependencies; value.Entitlement = nil; return value }(), wantConfigurationGate: true},
		{name: "missing identity", dependencies: func() cacheControlRuntimeDependencies { value := dependencies; value.Identity = nil; return value }(), wantConfigurationGate: true},
		{name: "unconfigured identity", dependencies: func() cacheControlRuntimeDependencies {
			value := dependencies
			value.Identity = &identity.Service{}
			return value
		}(), wantConfigurationGate: true},
		{name: "missing IAM", dependencies: func() cacheControlRuntimeDependencies { value := dependencies; value.IAM = nil; return value }(), wantConfigurationGate: true},
		{name: "unconfigured IAM", dependencies: func() cacheControlRuntimeDependencies {
			value := dependencies
			value.IAM = &iamlock.Authorizer{}
			return value
		}(), wantConfigurationGate: true},
		{name: "invalid worker config", configure: func(config *cacheControlRuntimeConfig) { config.Worker = cachecontrolruntime.Config{} }, dependencies: dependencies},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := config
			if test.configure != nil {
				test.configure(&candidate)
			}
			runtime, err := buildCacheControlRuntime(candidate, test.dependencies)
			if err == nil || runtime != nil {
				t.Fatalf("enabled cache control runtime = (%v, %v), want fail closed", runtime, err)
			}
			if test.wantConfigurationGate && err.Error() != "cache control runtime configuration is incomplete" {
				t.Fatalf("enabled cache control runtime error = %v, want configuration gate", err)
			}
		})
	}
	for length := 1; length < 32; length++ {
		candidate := config
		candidate.CursorKey = bytes.Repeat([]byte{0x41}, length)
		runtime, err := buildCacheControlRuntime(candidate, dependencies)
		if err == nil || err.Error() != "cache control runtime configuration is incomplete" || runtime != nil {
			t.Fatalf("%d-byte cursor key runtime = (%v, %v), want configuration gate", length, runtime, err)
		}
	}
}

func TestCacheControlRuntimeHandlerFactoryDelegatesAuthentication(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	runtime := newCacheControlRuntimeTestSubject(dependencies, &fakeCacheControlWorker{configured: true})
	factory := runtime.HandlerFactory()
	if factory == nil {
		t.Fatal("cache control handler factory is nil")
	}
	if handler, err := factory(nil); err == nil || handler != nil {
		t.Fatalf("nil authentication handler = (%v, %v), want error", handler, err)
	}

	authenticateCalls := 0
	handler, err := factory(func(*http.Request) (identity.Principal, error) {
		authenticateCalls++
		return identity.Principal{}, identity.ErrInvalidSession
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/cache-operations?limit=1", nil)
	request.Header.Set("Authorization", "Bearer invalid-runtime-token")
	request.Header.Set("X-Request-ID", "cache-control-runtime-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || authenticateCalls != 1 {
		t.Fatalf("authentication delegation status=%d calls=%d", response.Code, authenticateCalls)
	}
}

func TestCacheControlRuntimeHandlerFactoryFailsClosedOnHandlerConstruction(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	runtime := newCacheControlRuntimeTestSubject(dependencies, &fakeCacheControlWorker{configured: true})
	runtime.handlerDependencies.Identity = nil
	factory := runtime.HandlerFactory()
	handler, err := factory(func(*http.Request) (identity.Principal, error) {
		return identity.Principal{}, identity.ErrInvalidSession
	})
	if err == nil || handler != nil {
		t.Fatalf("invalid production handler = (%v, %v), want error", handler, err)
	}
}

func TestCacheControlRuntimeReadyObservesPrematureExit(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	workerErr := errors.New("cache worker failed")
	worker := &fakeCacheControlWorker{configured: true, runErr: workerErr}
	runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
	if err := runtime.Ready(); err == nil {
		t.Fatal("cache runtime reported ready before Run")
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, workerErr) {
		t.Fatalf("cache runtime Run() error = %v, want worker error", err)
	}
	if err := runtime.Ready(); !errors.Is(err, workerErr) {
		t.Fatalf("cache runtime readiness after terminal exit = %v, want worker error", err)
	}

	unexpected := newCacheControlRuntimeTestSubject(dependencies, &fakeCacheControlWorker{configured: true})
	err := unexpected.Run(t.Context())
	if err == nil || err.Error() != "cache control runtime failed" {
		t.Fatalf("nil worker exit error = %v, want safe terminal error", err)
	}
	if readyErr := unexpected.Ready(); readyErr == nil || readyErr.Error() != "cache control runtime failed" {
		t.Fatalf("nil worker exit readiness = %v, want safe terminal error", readyErr)
	}
}

func TestCacheControlRuntimeRunCancellationAndCloseOwnership(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	started := make(chan struct{})
	worker := &fakeCacheControlWorker{configured: true, waitForCancellation: true, started: started}
	runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
	ctx, cancel := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(ctx) }()
	<-started
	if err := runtime.Ready(); err != nil {
		t.Fatalf("running cache runtime readiness = %v", err)
	}
	cancel()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cache runtime cancellation error = %v", err)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("stopped cache runtime reported ready")
	}

	connectionWasClosed := dependencies.NATS.IsClosed()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(t.Context()); err == nil {
		t.Fatal("closed cache runtime restarted")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if worker.closeCalls.Load() != 1 {
		t.Fatalf("cache worker close calls = %d, want 1", worker.closeCalls.Load())
	}
	if dependencies.NATS.IsClosed() != connectionWasClosed {
		t.Fatal("cache runtime closed the caller-owned NATS connection")
	}
	if dependencies.Pool.Config() == nil {
		t.Fatal("cache runtime closed or invalidated the caller-owned pool")
	}
	if worker.configuredPool != dependencies.Pool || worker.configuredNATS != dependencies.NATS {
		t.Fatal("cache runtime readiness did not check caller-owned dependencies")
	}
}

func TestCacheControlRuntimeCloseCancelsAndWaitsForRun(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	started := make(chan struct{})
	cancelObserved := make(chan struct{})
	workerClosed := make(chan struct{})
	releaseExit := make(chan struct{})
	worker := &fakeCacheControlWorker{
		configured: true,
		run: func(ctx context.Context, _ func(error)) error {
			close(started)
			<-ctx.Done()
			close(cancelObserved)
			<-releaseExit
			return ctx.Err()
		},
		close: func() error {
			close(workerClosed)
			return nil
		},
	}
	runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
	parent, cancelParent := context.WithCancel(t.Context())
	defer cancelParent()
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(parent) }()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case <-cancelObserved:
	case err := <-closeDone:
		cancelParent()
		close(releaseExit)
		<-runDone
		t.Fatalf("cache runtime Close returned before canceling Run: %v", err)
	case <-time.After(2 * time.Second):
		cancelParent()
		close(releaseExit)
		<-runDone
		t.Fatal("cache runtime Close did not cancel Run")
	}
	<-workerClosed
	select {
	case err := <-closeDone:
		close(releaseExit)
		<-runDone
		t.Fatalf("cache runtime Close returned before Run exited: %v", err)
	default:
	}
	close(releaseExit)
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cache runtime Run() after Close = %v, want canceled", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestCacheControlRuntimeCloseRedactsWorkerError(t *testing.T) {
	const sensitiveSentinel = "cache-runtime-close-secret-must-not-leak"
	closeCause := errors.New(sensitiveSentinel)
	worker := &fakeCacheControlWorker{close: func() error { return closeCause }}
	runtime := newCacheControlRuntimeTestSubject(configuredCacheControlRuntimeDependencies(t), worker)

	first := runtime.Close()
	if !errors.Is(first, closeCause) {
		t.Fatal("cache runtime Close() lost worker error identity")
	}
	if first.Error() != "cache control runtime close failed" || strings.Contains(first.Error(), sensitiveSentinel) {
		t.Errorf("cache runtime Close() exposed worker error text: %v", first)
	}
	second := runtime.Close()
	if second != first || !errors.Is(second, closeCause) {
		t.Fatal("repeated cache runtime Close() did not preserve the first worker error")
	}
	if second.Error() != "cache control runtime close failed" || strings.Contains(second.Error(), sensitiveSentinel) {
		t.Errorf("repeated cache runtime Close() exposed worker error text: %v", second)
	}
	if worker.closeCalls.Load() != 1 {
		t.Fatalf("cache worker close calls = %d, want 1", worker.closeCalls.Load())
	}
}

func TestCacheControlRuntimeRunCannotCrossTerminalTransition(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondConfigured := make(chan struct{})
	releaseSecondConfigured := make(chan struct{})
	var configuredCalls atomic.Int32
	var runSequence atomic.Int32
	firstErr := errors.New("first cache worker fatal")
	secondErr := errors.New("second cache worker fatal")
	worker := &fakeCacheControlWorker{
		configured: true,
		configuredFor: func(*pgxpool.Pool, *nats.Conn) bool {
			if configuredCalls.Add(1) == 2 {
				close(secondConfigured)
				<-releaseSecondConfigured
			}
			return true
		},
		run: func(context.Context, func(error)) error {
			if runSequence.Add(1) == 1 {
				close(firstStarted)
				<-releaseFirst
				return firstErr
			}
			return secondErr
		},
	}
	runtime := newCacheControlRuntimeTestSubject(dependencies, worker)

	firstDone := make(chan error, 1)
	go func() { firstDone <- runtime.Run(t.Context()) }()
	<-firstStarted
	secondDone := make(chan error, 1)
	go func() { secondDone <- runtime.Run(t.Context()) }()

	select {
	case err := <-secondDone:
		if err == nil || !strings.Contains(err.Error(), "already running") {
			t.Fatalf("concurrent cache runtime Run() error = %v, want already running", err)
		}
	case <-secondConfigured:
		close(releaseFirst)
		if err := <-firstDone; !errors.Is(err, firstErr) {
			t.Fatalf("first cache runtime Run() error = %v, want %v", err, firstErr)
		}
		close(releaseSecondConfigured)
		err := <-secondDone
		t.Fatalf("second Run crossed terminal transition: error=%v calls=%d", err, worker.runCalls.Load())
	case <-time.After(2 * time.Second):
		t.Fatal("second cache runtime Run() did not resolve")
	}
	close(releaseFirst)
	if err := <-firstDone; !errors.Is(err, firstErr) {
		t.Fatalf("first cache runtime Run() error = %v, want %v", err, firstErr)
	}
	close(releaseSecondConfigured)
	if err := runtime.Ready(); !errors.Is(err, firstErr) {
		t.Fatalf("terminal cache runtime readiness = %v, want first fatal", err)
	}
	if err := runtime.Run(t.Context()); err == nil {
		t.Fatal("terminal cache runtime restarted")
	}
	if worker.runCalls.Load() != 1 {
		t.Fatalf("cache worker Run calls = %d, want 1", worker.runCalls.Load())
	}
}

func TestCacheControlRuntimeCloseWinsDuringRunPrecheck(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	configuredEntered := make(chan struct{})
	releaseConfigured := make(chan struct{})
	closeEntered := make(chan struct{})
	worker := &fakeCacheControlWorker{
		configured: true,
		configuredFor: func(*pgxpool.Pool, *nats.Conn) bool {
			close(configuredEntered)
			<-releaseConfigured
			return true
		},
		close: func() error {
			close(closeEntered)
			return nil
		},
	}
	runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()
	<-configuredEntered
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case <-closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("cache runtime Close did not reach worker during Run precheck")
	}
	close(releaseConfigured)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err == nil {
		t.Fatal("cache runtime Run succeeded after Close won precheck race")
	}
	if worker.runCalls.Load() != 0 {
		t.Fatalf("closed cache worker Run calls = %d, want 0", worker.runCalls.Load())
	}
}

func TestCacheControlRuntimeTerminalRunReadyInterleave(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	started := make(chan struct{})
	releaseRun := make(chan struct{})
	returning := make(chan struct{})
	terminalErr := errors.New("interleaved cache worker fatal")
	var workerAlive atomic.Bool
	workerAlive.Store(true)
	worker := &fakeCacheControlWorker{
		configuredFor: func(*pgxpool.Pool, *nats.Conn) bool {
			return workerAlive.Load()
		},
		run: func(context.Context, func(error)) error {
			close(started)
			<-releaseRun
			workerAlive.Store(false)
			close(returning)
			return terminalErr
		},
	}
	runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
	firstDone := make(chan error, 1)
	go func() { firstDone <- runtime.Run(t.Context()) }()
	<-started

	runtime.lifecycleMu.Lock()
	close(releaseRun)
	<-returning
	secondDone := make(chan error, 1)
	readyDone := make(chan error, 1)
	go func() { secondDone <- runtime.Run(t.Context()) }()
	go func() { readyDone <- runtime.Ready() }()
	runtime.lifecycleMu.Unlock()

	if err := <-secondDone; err == nil {
		t.Fatal("second cache runtime Run crossed terminal interleave")
	}
	if err := <-readyDone; err == nil {
		t.Fatal("cache runtime reported ready while terminal transition was pending")
	}
	if err := <-firstDone; !errors.Is(err, terminalErr) {
		t.Fatalf("first cache runtime Run() error = %v, want terminal fatal", err)
	}
	if err := runtime.Ready(); !errors.Is(err, terminalErr) {
		t.Fatalf("final cache runtime readiness = %v, want terminal fatal", err)
	}
	if worker.runCalls.Load() != 1 {
		t.Fatalf("interleaved cache worker Run calls = %d, want 1", worker.runCalls.Load())
	}
}

func TestCacheControlRuntimeCancellationPreservesIndependentFatal(t *testing.T) {
	const sensitiveSentinel = "cache-runtime-terminal-secret-must-not-leak"
	tests := []struct {
		name         string
		deadline     bool
		result       func(error, error) error
		wantCanceled bool
		wantDeadline bool
	}{
		{name: "independent", result: func(_ error, fatalErr error) error { return fatalErr }},
		{name: "joined cancellation and fatal", result: func(ctxErr, fatalErr error) error {
			return errors.Join(ctxErr, fatalErr)
		}, wantCanceled: true},
		{name: "joined deadline and fatal", deadline: true, result: func(ctxErr, fatalErr error) error {
			return errors.Join(ctxErr, fatalErr)
		}, wantDeadline: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := configuredCacheControlRuntimeDependencies(t)
			started := make(chan struct{})
			fatalErr := errors.New(sensitiveSentinel)
			worker := &fakeCacheControlWorker{
				configured: true,
				run: func(ctx context.Context, _ func(error)) error {
					close(started)
					<-ctx.Done()
					return test.result(ctx.Err(), fatalErr)
				},
			}
			runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
			var ctx context.Context
			var cancel context.CancelFunc
			if test.deadline {
				ctx, cancel = context.WithTimeout(t.Context(), 25*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- runtime.Run(ctx) }()
			<-started
			if !test.deadline {
				cancel()
			}
			runErr := <-done
			if !errors.Is(runErr, fatalErr) || errors.Is(runErr, context.Canceled) != test.wantCanceled ||
				errors.Is(runErr, context.DeadlineExceeded) != test.wantDeadline {
				t.Fatal("cache runtime Run() lost terminal error identity")
			}
			if runErr.Error() != "cache control runtime failed" || strings.Contains(runErr.Error(), sensitiveSentinel) {
				t.Error("cache runtime Run() exposed terminal error text")
			}
			readyErr := runtime.Ready()
			if !errors.Is(readyErr, fatalErr) || errors.Is(readyErr, context.Canceled) != test.wantCanceled ||
				errors.Is(readyErr, context.DeadlineExceeded) != test.wantDeadline {
				t.Fatal("cache runtime readiness lost terminal error identity")
			}
			if readyErr.Error() != "cache control runtime failed" || strings.Contains(readyErr.Error(), sensitiveSentinel) {
				t.Error("cache runtime readiness exposed terminal error text")
			}
		})
	}
}

func TestCacheControlRuntimeParentContextTerminationIsNotWrapped(t *testing.T) {
	tests := []struct {
		name     string
		deadline bool
		want     error
	}{
		{name: "canceled", want: context.Canceled},
		{name: "deadline", deadline: true, want: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			worker := &fakeCacheControlWorker{
				configured: true,
				run: func(ctx context.Context, _ func(error)) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				},
			}
			runtime := newCacheControlRuntimeTestSubject(configuredCacheControlRuntimeDependencies(t), worker)
			var ctx context.Context
			var cancel context.CancelFunc
			if test.deadline {
				ctx, cancel = context.WithTimeout(t.Context(), 25*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(t.Context())
			}
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- runtime.Run(ctx) }()
			<-started
			if !test.deadline {
				cancel()
			}
			runErr := <-done
			if !errors.Is(runErr, test.want) || runErr.Error() != test.want.Error() {
				t.Fatalf("cache runtime Run() error = %v, want unwrapped %v", runErr, test.want)
			}
			readyErr := runtime.Ready()
			if readyErr == nil || readyErr.Error() != "cache control runtime is unavailable" || errors.Is(readyErr, test.want) {
				t.Fatalf("cache runtime readiness after parent stop = %v, want non-terminal unavailable", readyErr)
			}
		})
	}
}

func TestCacheControlRuntimeOperationLogClassifiesAndRedactsWorkerError(t *testing.T) {
	const sensitiveSentinel = "cache-secret-token-should-not-be-logged"
	fatalErr := errors.New(sensitiveSentinel)
	tests := []struct {
		name         string
		workerErr    error
		wantCategory string
	}{
		{name: "canceled", workerErr: context.Canceled, wantCategory: "canceled"},
		{name: "deadline", workerErr: context.DeadlineExceeded, wantCategory: "timeout"},
		{name: "joined canceled and fatal", workerErr: errors.Join(context.Canceled, fatalErr), wantCategory: "internal"},
		{name: "joined deadline and fatal", workerErr: errors.Join(context.DeadlineExceeded, fatalErr), wantCategory: "internal"},
		{name: "fatal", workerErr: fatalErr, wantCategory: "internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := configuredCacheControlRuntimeDependencies(t)
			worker := &fakeCacheControlWorker{
				configured: true,
				run: func(_ context.Context, onError func(error)) error {
					onError(test.workerErr)
					return test.workerErr
				},
			}
			runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
			var captured bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&captured, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })

			if err := runtime.Run(t.Context()); err == nil {
				t.Fatal("cache runtime Run() unexpectedly succeeded")
			}
			logged := captured.String()
			if strings.Contains(logged, sensitiveSentinel) {
				t.Fatalf("cache runtime log exposed worker error: %s", logged)
			}
			if !strings.Contains(logged, "cache control runtime operation failed") ||
				!strings.Contains(logged, `"error_category":"`+test.wantCategory+`"`) {
				t.Fatalf("cache runtime log = %s, want fixed message and %s category", logged, test.wantCategory)
			}
		})
	}
}

type fakeCacheControlWorker struct {
	configured          bool
	runErr              error
	waitForCancellation bool
	started             chan struct{}
	configuredFor       func(*pgxpool.Pool, *nats.Conn) bool
	run                 func(context.Context, func(error)) error
	close               func() error
	configuredPool      *pgxpool.Pool
	configuredNATS      *nats.Conn
	runCalls            atomic.Int32
	closeCalls          atomic.Int32
}

func (worker *fakeCacheControlWorker) ConfiguredFor(pool *pgxpool.Pool, connection *nats.Conn) bool {
	worker.configuredPool = pool
	worker.configuredNATS = connection
	if worker.configuredFor != nil {
		return worker.configuredFor(pool, connection)
	}
	return worker.configured
}

func (worker *fakeCacheControlWorker) Run(ctx context.Context, onError func(error)) error {
	worker.runCalls.Add(1)
	if worker.run != nil {
		return worker.run(ctx, onError)
	}
	if worker.started != nil {
		close(worker.started)
	}
	if worker.waitForCancellation {
		<-ctx.Done()
		return ctx.Err()
	}
	return worker.runErr
}

func (worker *fakeCacheControlWorker) Close() error {
	worker.closeCalls.Add(1)
	if worker.close != nil {
		return worker.close()
	}
	return nil
}

type fakeCacheControlLeaseReader struct{}

func (fakeCacheControlLeaseReader) Exists(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func configuredCacheControlRuntimeDependencies(t *testing.T) cacheControlRuntimeDependencies {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgres://cache-control-runtime.invalid/runtime")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("c", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x42}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return cacheControlRuntimeDependencies{
		Pool: pool, NATS: &nats.Conn{}, NodeLeases: fakeCacheControlLeaseReader{},
		Entitlement: entitlementguard.NewGuard(pool, time.Now, nil), Identity: identityService, IAM: authorizer,
	}
}

func newCacheControlRuntimeTestSubject(
	dependencies cacheControlRuntimeDependencies,
	worker cacheControlWorker,
) *cacheControlRuntime {
	runtime := &cacheControlRuntime{
		worker: worker, pool: dependencies.Pool, nats: dependencies.NATS,
		handlerConfig: cachecontrolhttp.ProductionConfig{
			CursorKey: bytes.Repeat([]byte{0x51}, 32), Clock: time.Now,
		},
		handlerDependencies: cachecontrolhttp.ProductionDependencies{
			Pool: dependencies.Pool, Entitlement: dependencies.Entitlement,
			Identity: dependencies.Identity, IAM: dependencies.IAM,
		},
	}
	return runtime
}

var _ nodepresence.LeaseReader = fakeCacheControlLeaseReader{}
