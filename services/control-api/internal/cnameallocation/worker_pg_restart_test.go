package cnameallocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgRestartError is what pgx returns on a pooled connection after PostgreSQL
// restarts (pg_ctl restart, unattended-upgrade).
func pgRestartError() *pgconn.PgError {
	return &pgconn.PgError{Severity: "FATAL", Code: "57P01",
		Message: "terminating connection due to administrator command"}
}

type failingTenants struct{ err error }

func (tenants failingTenants) PendingTenants(context.Context, int) ([]uuid.UUID, error) {
	return nil, tenants.err
}

// PendingTenants used to replace the database error with a bare
// ErrUnavailable, so control-api could not see the 57P01 cause and exited.
func TestUnavailableKeepsPostgresCause(t *testing.T) {
	err := unavailable(pgRestartError())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "57P01" {
		t.Fatalf("PostgreSQL cause lost: %v", err)
	}
}

func TestWorkerRunReturnsPostgresCauseFromPendingTenants(t *testing.T) {
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker-pg-restart", LeaseDuration: time.Minute,
		PollInterval: time.Hour}, WorkerDependencies{
		Tenants: failingTenants{err: unavailable(pgRestartError())},
		Claims:  &transientRetryClaims{}, Targets: &transientRetryTargets{}, Reconcile: &transientRetryReconcile{},
	})
	if err != nil {
		t.Fatal(err)
	}
	runErr := worker.Run(t.Context())
	var pgErr *pgconn.PgError
	if !errors.Is(runErr, ErrUnavailable) || !errors.As(runErr, &pgErr) || pgErr.Code != "57P01" {
		t.Fatalf("Run() = %v, want ErrUnavailable wrapping 57P01", runErr)
	}
}

// mapError used to format the database cause with %v, so errors.As could not
// reach the PgError behind ErrUnavailable / ErrRetryable.
func TestMapErrorKeepsPostgresCause(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{{"57P01", ErrUnavailable}, {"40P01", ErrRetryable}} {
		err := mapError(&pgconn.PgError{Code: tc.code})
		var pgErr *pgconn.PgError
		if !errors.Is(err, tc.want) || !errors.As(err, &pgErr) || pgErr.Code != tc.code {
			t.Fatalf("mapError(%s) = %v, want %v wrapping the PgError", tc.code, err, tc.want)
		}
	}
}
