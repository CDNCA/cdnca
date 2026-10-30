package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/jackc/pgx/v5/pgconn"
)

// After a PostgreSQL restart the CNAME worker's PendingTenants fails with
// 57P01. The worker must be retried by runWithDBBackoff, not reported as a
// terminal error (which made control-api exit three times on 73).
func cnamePGRestartError() error {
	return fmt.Errorf("%w: %w", cnameallocation.ErrUnavailable, &pgconn.PgError{Severity: "FATAL", Code: "57P01",
		Message: "terminating connection due to administrator command"})
}

func TestCNAMEUnavailableWrappingPGRestartIsTransient(t *testing.T) {
	if !isTransientDBError(cnamePGRestartError()) {
		t.Fatal("ErrUnavailable wrapping 57P01 is not treated as a transient DB error")
	}
	// The retry dials while PostgreSQL is still down: connection refused.
	refused := fmt.Errorf("%w: failed to connect: %w", cnameallocation.ErrUnavailable,
		&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	if !isTransientDBError(refused) {
		t.Fatalf("%v is not treated as a transient DB error", refused)
	}
	if isTransientDBError(cnameallocation.ErrUnavailable) {
		t.Fatal("bare ErrUnavailable has no DB cause and must not be treated as transient")
	}
}

func TestRunWithDBBackoffRetriesCNAMEWorkerAfterPGRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- runWithDBBackoff(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "CNAME allocation worker",
			time.Minute, func(ctx context.Context) error {
				calls++
				if calls == 1 {
					return cnamePGRestartError()
				}
				cancel()
				<-ctx.Done()
				return ctx.Err()
			})
	}()
	select {
	case err := <-done:
		if calls != 2 || !errors.Is(err, context.Canceled) {
			t.Fatalf("runWithDBBackoff() = %v after %d calls, want retry then context.Canceled", err, calls)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runWithDBBackoff did not retry the worker")
	}
}
