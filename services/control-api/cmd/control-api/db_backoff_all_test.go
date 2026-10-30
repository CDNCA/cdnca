package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// On a test control plane unattended upgrades restarted PostgreSQL nine
// times and control-api exited four times: runtimes whose Run returned a
// 57P01 / connection refused error were reported as terminal. Each runtime
// below is now wrapped by runWithDBBackoff at its main.go call site.

func pgTerminatedError() error {
	return &pgconn.PgError{Severity: "FATAL", Code: "57P01",
		Message: "terminating connection due to administrator command"}
}

// runBackedOff drives runWithDBBackoff the way main.go does and reports
// whether the result would have been sent to backgroundErrors (process exit).
func runBackedOff(t *testing.T, name string, run func(ctx context.Context, stop func()) error) (calls int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var count atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- runWithDBBackoff(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), name, time.Minute,
			func(ctx context.Context) error {
				count.Add(1)
				// stop ends the test like a process shutdown once the retried
				// attempt has done its work.
				return run(ctx, cancel)
			})
	}()
	select {
	case err := <-done:
		if ctx.Err() == nil {
			t.Fatalf("%s: runWithDBBackoff returned %v while the process was still running (would exit)", name, err)
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: runWithDBBackoff = %v, want nil or context.Canceled", name, err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("%s: runWithDBBackoff did not retry", name)
	}
	return int(count.Load())
}

// The fake Run fails once with 57P01, then succeeds: the process must not be
// taken down, and Run must be called exactly twice.
func TestRunWithDBBackoffKeepsProcessForEveryWrappedRuntime(t *testing.T) {
	for _, name := range []string{
		"security activation worker",
		"edge deployment runtime",
		"entitlement revocation runtime",
		"signer revocation consumer",
	} {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			calls := runBackedOff(t, name, func(ctx context.Context, stop func()) error {
				attempts++
				if attempts == 1 {
					return fmt.Errorf("%s: %w", name, pgTerminatedError())
				}
				stop()
				<-ctx.Done()
				return ctx.Err()
			})
			if calls != 2 {
				t.Fatalf("Run called %d times, want 2", calls)
			}
		})
	}
}

// A non-database failure is still terminal: runWithDBBackoff must return it
// immediately so systemd restarts the process.
func TestRunWithDBBackoffStillExitsOnNonDatabaseFailure(t *testing.T) {
	sentinel := errors.New("listener closed")
	calls := 0
	err := runWithDBBackoff(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), "x", time.Minute,
		func(context.Context) error { calls++; return sentinel })
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("runWithDBBackoff = %v after %d calls, want the sentinel after 1 call", err, calls)
	}
}

// The security activation worker returns its reconcile error unchanged, so a
// 57P01 from loadWorkerItems reaches runWithDBBackoff as is.
func TestSecurityActivationReconcileErrorIsTransient(t *testing.T) {
	err := fmt.Errorf("reconcile security activation %s: %w", uuid.New(), pgTerminatedError())
	if !isTransientDBError(err) {
		t.Fatalf("%v is not treated as transient", err)
	}
}

// The edge deployment runtime is re-run by runWithDBBackoff; the wrapped Run
// must survive a 57P01 from one of its workers and run again.
func TestEdgeDeploymentRuntimeSurvivesPGRestartUnderBackoff(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	runtime := &edgeDeploymentRuntime{
		connection: fakeNATSRuntimeConnection{connected: true},
		workers: []runtimeWorker{fakeRuntimeWorker{run: func(ctx context.Context) error {
			mu.Lock()
			attempts++
			attempt := attempts
			mu.Unlock()
			if attempt == 1 {
				return pgTerminatedError()
			}
			return nil
		}}},
	}
	// runRequiredWorkers reports a nil worker exit as an error; the second
	// attempt's nil is therefore turned into a non-DB error and returned. That
	// is fine: what matters is that the 57P01 attempt was retried.
	err := runWithDBBackoff(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)),
		"edge deployment runtime", time.Minute, runtime.Run)
	mu.Lock()
	defer mu.Unlock()
	if attempts != 2 {
		t.Fatalf("edge deployment runtime ran %d times (last error %v), want a retry after 57P01", attempts, err)
	}
}

// Entitlement revocation: a database failure is returned (not deferred), so
// runWithDBBackoff re-runs it; the retry must clear the previous attempt's
// terminal error so readiness can recover.
func TestEntitlementRevocationRuntimeRetriesAfterPGRestart(t *testing.T) {
	syncer := &flakySyncer{err: fmt.Errorf("restore entitlement revocation state: %w", pgTerminatedError())}
	runtime := newTestEntitlementRevocationRuntime(&fakeEntitlementRevocationRefresher{}, syncer,
		&fakeEntitlementRevocationStore{})
	runtime.wait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	first := runtime.Run(context.Background())
	if !isTransientDBError(first) {
		t.Fatalf("first Run = %v, want a transient DB error", first)
	}
	runtime.terminalMu.RLock()
	terminal := runtime.terminalError
	runtime.terminalMu.RUnlock()
	if terminal == nil {
		t.Fatal("failed Run did not record its terminal error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncer.onSuccess = cancel
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("retried Run = %v, want context.Canceled", err)
	}
	runtime.terminalMu.RLock()
	terminal = runtime.terminalError
	runtime.terminalMu.RUnlock()
	if terminal != nil {
		t.Fatalf("retried Run kept the previous terminal error %v", terminal)
	}
}

type flakyCore struct {
	err       error
	calls     atomic.Int64
	onSuccess func()
}

// RunOnce fails on the first call only.
func (core *flakyCore) RunOnce(context.Context) (int, error) {
	if core.calls.Add(1) == 1 {
		return 0, core.err
	}
	if core.onSuccess != nil {
		core.onSuccess()
	}
	return 0, nil
}

type flakySyncer struct {
	err       error
	calls     int
	onSuccess func()
}

func (syncer *flakySyncer) SyncOnce(context.Context) (entitlementguard.RevocationSnapshot, error) {
	syncer.calls++
	if syncer.calls == 1 {
		return entitlementguard.RevocationSnapshot{}, syncer.err
	}
	if syncer.onSuccess != nil {
		syncer.onSuccess()
	}
	return entitlementguard.RevocationSnapshot{}, nil
}
