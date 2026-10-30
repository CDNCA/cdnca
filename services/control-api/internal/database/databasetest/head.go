package databasetest

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MigratedPool returns a pool on a database at the release migration head: a
// clone of TEST_DATABASE_TEMPLATE when one is configured, else a fresh schema
// in TEST_DATABASE_URL migrated up. Either way the schema is dropped on
// cleanup.
//
// A test that exercises current runtime code (services, stores, audit.Append)
// must run at the head. Replaying migrations only up to an old version leaves
// out columns and tables that code writes today (for example the 361 audit
// columns), and replaying them by fixed number breaks every time a migration
// is added. Only a test of one migration's own up/down should stop at an old
// version, through MigrateThrough.
func MigratedPool(t testing.TB, configure func(*pgxpool.Config)) *pgxpool.Pool {
	t.Helper()
	if pool := ClonedMigratedPool(t, configure); pool != nil {
		return pool
	}
	return FreshSchemaPool(t, "head_test", configure, func(ctx context.Context, pool *pgxpool.Pool) error {
		return database.Migrate(ctx, pool, "up")
	})
}

// FreshSchemaPool creates schema <prefix>_<uuid> in TEST_DATABASE_URL, opens a
// pool whose search_path is that schema, runs prepare (nil: nothing) and drops
// the schema on cleanup. Skips when TEST_DATABASE_URL is not set.
func FreshSchemaPool(
	t testing.TB,
	prefix string,
	configure func(*pgxpool.Config),
	prepare func(context.Context, *pgxpool.Pool) error,
) *pgxpool.Pool {
	t.Helper()
	if !templateName.MatchString(prefix) {
		t.Fatalf("unsafe schema prefix %q", prefix)
	}
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	identifier := pgx.Identifier{prefix + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = identifier[0]
	if configure != nil {
		configure(config)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		dropCtx, dropCancel := CleanupContext()
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, "DROP SCHEMA "+identifier.Sanitize()+" CASCADE"); err != nil {
			t.Logf("drop test schema %s (left behind): %v", identifier[0], err)
		}
		admin.Close()
	})
	if prepare != nil {
		if err := prepare(ctx, pool); err != nil {
			t.Fatalf("prepare schema %s: %v", identifier[0], err)
		}
	}
	return pool
}

// MigratedThroughPool returns a fresh schema migrated through target only
// (migrations 1..target), for a test of one migration's own up/down round
// trip. Runtime code must not be exercised on it; use MigratedPool.
func MigratedThroughPool(t testing.TB, prefix string, target int64) *pgxpool.Pool {
	t.Helper()
	return FreshSchemaPool(t, prefix, nil, func(ctx context.Context, pool *pgxpool.Pool) error {
		return MigrateThrough(ctx, pool, "up", target)
	})
}

// AddUnifiedAuditColumns adds the audit_events columns of migration 361
// (unified log) and 491 (user_agent) to a schema migrated through an older version, so today's
// audit.Append can record events while a test exercises that older
// migration's own down guard with live facts. Use it only for such a guard
// test; nothing else of 361 is applied.
func AddUnifiedAuditColumns(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `ALTER TABLE audit_events
		ADD COLUMN category text NOT NULL DEFAULT 'other',
		ADD COLUMN actor_kind text NOT NULL DEFAULT 'system',
		ADD COLUMN actor_ref text NOT NULL DEFAULT '',
		ADD COLUMN source_ip text NOT NULL DEFAULT '',
		ADD COLUMN reason_code text NOT NULL DEFAULT '',
		ADD COLUMN changes jsonb NOT NULL DEFAULT '[]'::jsonb,
		ADD COLUMN user_agent text NOT NULL DEFAULT ''`); err != nil {
		t.Fatalf("add unified audit columns: %v", err)
	}
}
