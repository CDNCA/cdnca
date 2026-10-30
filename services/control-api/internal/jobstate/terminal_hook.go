package jobstate

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TerminalHook ends a producer's projection of a job that jobstate itself
// ended without its worker: retries exhausted (finalizeExhausted) or
// cancelled (CancelTx). It runs in the transaction that ends the job; code is
// CodeRetriesExhausted or CodeCancelled. A CNAME
// allocation job ended retries_exhausted left its site "generating" forever.
type TerminalHook func(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, code string, now time.Time) error

var terminalHooks sync.Map // kind -> TerminalHook

// RegisterTerminalHook sets the hook of kind (one per kind; the last wins).
func RegisterTerminalHook(kind string, hook TerminalHook) {
	terminalHooks.Store(kind, hook)
}

// runTerminalHook runs kind's hook under a savepoint: a statement it cannot
// complete is rolled back and logged, so one inconsistent projection never
// blocks the claims or the cancellation around it. A hook whose writes have
// deferred constraint triggers checks them itself (SET CONSTRAINTS ...
// IMMEDIATE) so a violation is caught inside the savepoint.
func runTerminalHook(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, kind, code string, now time.Time) error {
	value, ok := terminalHooks.Load(kind)
	if !ok {
		return nil
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	hookErr := value.(TerminalHook)(ctx, savepoint, tenantID, jobID, code, now)
	if hookErr == nil {
		hookErr = savepoint.Commit(ctx)
	}
	if hookErr != nil {
		if err := savepoint.Rollback(ctx); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Warn("background job terminal hook failed", "kind", kind, "tenant_id", tenantID,
			"job_id", jobID, "code", code, "error", hookErr)
	}
	return nil
}
