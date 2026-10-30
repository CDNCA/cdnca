//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestL4SessionLogMigration: 328 leaves streams unlogged, keeps the log off
// v1 streams, and refuses to roll back once a log or its history exists.
func TestL4SessionLogMigration(t *testing.T) {
	const version = 328
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "session-log-328", now)
	legacy := uuid.New()
	seedL4Forward214(t, pool, legacy, scope, subscription, user, "Legacy plain", 19498, now)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT session_log_enabled FROM l4_forwards WHERE id=$1`, legacy).Scan(&enabled); err != nil || enabled {
		t.Fatalf("existing stream after 328: %v err=%v", enabled, err)
	}
	var pgErr *pgconn.PgError
	if _, err := pool.Exec(ctx, `UPDATE l4_forwards SET session_log_enabled=true WHERE id=$1`, legacy); !errors.As(err, &pgErr) ||
		pgErr.Code != "23514" || pgErr.ConstraintName != "l4_forwards_session_log_328" {
		t.Fatalf("session log on a v1 stream: err=%v", err)
	}
	seedL4WriteReceipt214(t, pool, legacy, scope, user, "stream.update", "session-log-328-receipt", now)
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"session_log_enabled":true}'
		WHERE idempotency_key='session-log-328-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P3282" {
		t.Fatalf("down with session log history err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"session_log_enabled":false}'
		WHERE idempotency_key='session-log-328-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with only disabled responses: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
