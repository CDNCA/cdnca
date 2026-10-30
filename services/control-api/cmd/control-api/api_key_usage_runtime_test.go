package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeyusage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type blockingAPIKeyUsageWorker struct {
	closeCalls atomic.Int32
}

func (*blockingAPIKeyUsageWorker) TryRecord(uuid.UUID, time.Time) bool {
	return false
}

func (worker *blockingAPIKeyUsageWorker) Close(ctx context.Context) error {
	worker.closeCalls.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func TestAPIKeyUsageRuntimeUsesDefaultsAndRequiresPool(t *testing.T) {
	if runtime, err := newAPIKeyUsageRuntime(nil); runtime != nil || err == nil {
		t.Fatalf("nil-pool runtime = (%v, %v), want configuration error", runtime, err)
	}
	defaults := apikeyusage.DefaultConfig()
	poolConfig, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	configured, err := newAPIKeyUsageRuntime(pool)
	if err != nil {
		t.Fatal(err)
	}
	if configured.shutdownTimeout != defaults.ShutdownTimeout {
		t.Fatalf("shutdown timeout = %s, want DefaultConfig %s", configured.shutdownTimeout, defaults.ShutdownTimeout)
	}
	if err := configured.Close(); err != nil {
		t.Fatal(err)
	}

	worker := &blockingAPIKeyUsageWorker{}
	runtime := &apiKeyUsageRuntime{worker: worker, shutdownTimeout: time.Millisecond}
	if runtime.TryRecord(uuid.New(), time.Now()) {
		t.Fatal("worker rejection was not propagated")
	}
	started := time.Now()
	firstErr := runtime.Close()
	if !errors.Is(firstErr, context.DeadlineExceeded) || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("bounded close = (%v, %s)", firstErr, time.Since(started))
	}
	secondErr := runtime.Close()
	if !errors.Is(secondErr, context.DeadlineExceeded) || worker.closeCalls.Load() != 1 {
		t.Fatalf("idempotent close = (err=%v calls=%d)", secondErr, worker.closeCalls.Load())
	}
}

func TestNilAPIKeyUsageRuntimeIsClosedAndNonRecording(t *testing.T) {
	var runtime *apiKeyUsageRuntime
	if runtime.TryRecord(uuid.New(), time.Now()) {
		t.Fatal("nil runtime accepted an observation")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("nil runtime close: %v", err)
	}
}
