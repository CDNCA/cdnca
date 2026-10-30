package signerrevocationconsumer

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// control-api re-runs the consumer through runWithDBBackoff after a
// PostgreSQL restart. A Run that ended on a 57P01 from RestoreV2 must not
// leave the runtime single-use: the retry runs, and its readiness no longer
// carries the previous attempt's terminal error.
func TestProductionRuntimeRunsAgainAfterTransientDatabaseFailure(t *testing.T) {
	restart := &pgconn.PgError{Severity: "FATAL", Code: "57P01",
		Message: "terminating connection due to administrator command"}
	store := &productionStore{restoreErr: restart}
	runtime := newTestProductionRuntime(t, store, &productionFetcher{}, &productionSnapshotRuntime{}, time.Hour)
	var pgErr *pgconn.PgError
	if err := runtime.Run(t.Context()); !errors.As(err, &pgErr) || pgErr.Code != "57P01" {
		t.Fatalf("first Run = %v, want the 57P01 cause", err)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("failed runtime reported ready")
	}

	store.mu.Lock()
	store.restoreErr, store.waitForCancel = nil, true
	store.entered = make(chan struct{}, 1)
	entered := store.entered
	store.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("retried Run returned %v before refreshing", err)
	case <-time.After(5 * time.Second):
		t.Fatal("retried Run did not start")
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("retried runtime is not ready: %v", err)
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrProductionAlreadyRun) {
		t.Fatalf("concurrent Run = %v, want ErrProductionAlreadyRun", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("retried Run after Close = %v", err)
	}
}
