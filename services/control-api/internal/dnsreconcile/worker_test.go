package dnsreconcile

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeTenantSource struct{ tenants []uuid.UUID }

func (source fakeTenantSource) PendingTenants(context.Context, int) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), source.tenants...), nil
}

type fakeTenantRunner struct{ tenants []uuid.UUID }

func (runner *fakeTenantRunner) RunOnce(_ context.Context, tenantID uuid.UUID, _ string, _ int) ([]Task, error) {
	runner.tenants = append(runner.tenants, tenantID)
	return nil, nil
}

type retryTenantSource struct {
	calls  int
	second chan struct{}
}

func (source *retryTenantSource) PendingTenants(context.Context, int) ([]uuid.UUID, error) {
	source.calls++
	if source.calls == 1 {
		return nil, ErrUnavailable
	}
	if source.calls == 2 {
		close(source.second)
	}
	return nil, nil
}

type scriptedTenantRunner struct {
	tenants []uuid.UUID
	run     func(context.Context, uuid.UUID) error
}

func (runner *scriptedTenantRunner) RunOnce(ctx context.Context, tenantID uuid.UUID, _ string, _ int) ([]Task, error) {
	runner.tenants = append(runner.tenants, tenantID)
	if runner.run != nil {
		return nil, runner.run(ctx, tenantID)
	}
	return nil, nil
}

func TestWorkerRunRetriesEnumerationFailure(t *testing.T) {
	source := &retryTenantSource{second: make(chan struct{})}
	runner := &fakeTenantRunner{}
	worker, err := NewWorker(WorkerConfig{
		WorkerID: "dns-reconcile-retry", TenantLimit: 16, ClaimLimit: 8, PollInterval: 10 * time.Millisecond,
	}, WorkerDependencies{Tenants: source, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-source.second:
		cancel()
	case err := <-done:
		t.Fatalf("Run() stopped before retry: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Run() did not retry tenant enumeration")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error=%v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not stop after cancellation")
	}
	if len(runner.tenants) != 0 {
		t.Fatalf("runner tenants=%v, want none", runner.tenants)
	}
}

func TestWorkerRunOnceIsolatesTenantFailures(t *testing.T) {
	t.Run("continues after tenant error", func(t *testing.T) {
		tenantA, tenantB := uuid.New(), uuid.New()
		sentinel := errors.New("tenant A unavailable")
		runner := &scriptedTenantRunner{run: func(_ context.Context, tenantID uuid.UUID) error {
			if tenantID == tenantA {
				return sentinel
			}
			return nil
		}}
		worker, err := NewWorker(WorkerConfig{
			WorkerID: "dns-reconcile-isolation", TenantLimit: 16, ClaimLimit: 8, PollInterval: time.Second,
		}, WorkerDependencies{Tenants: fakeTenantSource{tenants: []uuid.UUID{tenantA, tenantB}}, Runner: runner})
		if err != nil {
			t.Fatal(err)
		}
		err = worker.RunOnce(t.Context())
		if !errors.Is(err, sentinel) || len(runner.tenants) != 2 ||
			runner.tenants[0] != tenantA || runner.tenants[1] != tenantB {
			t.Fatalf("RunOnce() error=%v tenants=%v", err, runner.tenants)
		}
	})

	t.Run("stops when context ends", func(t *testing.T) {
		tenantA, tenantB := uuid.New(), uuid.New()
		ctx, cancel := context.WithCancel(t.Context())
		runner := &scriptedTenantRunner{run: func(_ context.Context, tenantID uuid.UUID) error {
			if tenantID == tenantA {
				cancel()
				return context.Canceled
			}
			return nil
		}}
		worker, err := NewWorker(WorkerConfig{
			WorkerID: "dns-reconcile-context", TenantLimit: 16, ClaimLimit: 8, PollInterval: time.Second,
		}, WorkerDependencies{Tenants: fakeTenantSource{tenants: []uuid.UUID{tenantA, tenantB}}, Runner: runner})
		if err != nil {
			t.Fatal(err)
		}
		err = worker.RunOnce(ctx)
		if !errors.Is(err, context.Canceled) || len(runner.tenants) != 1 || runner.tenants[0] != tenantA {
			t.Fatalf("RunOnce() error=%v tenants=%v", err, runner.tenants)
		}
	})
}

func TestWorkerEnumeratesDurableQueuedTenantsWithoutGlobalTenantGuess(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	runner := &fakeTenantRunner{}
	worker, err := NewWorker(WorkerConfig{
		WorkerID: "dns-reconcile-worker", TenantLimit: 16, ClaimLimit: 8, PollInterval: time.Second,
	}, WorkerDependencies{Tenants: fakeTenantSource{tenants: []uuid.UUID{tenantA, tenantB}}, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.tenants) != 2 || runner.tenants[0] != tenantA || runner.tenants[1] != tenantB {
		t.Fatalf("processed tenants=%v", runner.tenants)
	}
}
