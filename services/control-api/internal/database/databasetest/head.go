package databasetest

import (
	"context"
	"net/url"
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

// FreshSchemaPool creates database <prefix>_<uuid> (from template0) on the
// TEST_DATABASE_URL server with a schema of the same name, opens a pool whose
// search_path is that schema, runs prepare (nil: nothing) and drops the
// database on cleanup. Skips when TEST_DATABASE_URL is not set.
//
// The schema gets its own database because migration guards read
// information_schema without a table_schema filter (e.g. 580 refuses with
// P5800 when any schema already has analytics_log_exports_v1.scope_generation),
// so a sibling schema at a later head in the shared database breaks them.
func FreshSchemaPool(
	t testing.TB,
	prefix string,
	configure func(*pgxpool.Config),
	prepare func(context.Context, *pgxpool.Pool) error,
) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	config, name := freshDatabase(t, os.Getenv("TEST_DATABASE_URL"), prefix)
	identifier := pgx.Identifier{name}
	schemaConfig := config.ConnConfig.Copy()
	schemaConn, err := pgx.ConnectConfig(ctx, schemaConfig)
	if err != nil {
		t.Fatal(err)
	}
	_, err = schemaConn.Exec(ctx, "CREATE SCHEMA "+identifier.Sanitize())
	_ = schemaConn.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = identifier[0]
	if configure != nil {
		configure(config)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	// Registered after the drop, so it runs first.
	t.Cleanup(pool.Close)
	if prepare != nil {
		if err := prepare(ctx, pool); err != nil {
			t.Fatalf("prepare schema %s: %v", identifier[0], err)
		}
	}
	return pool
}

// FreshDatabaseURL creates database <prefix>_<uuid> (from template0) on the
// server of base and returns base pointed at it; the database is dropped on
// cleanup. Skips when base is empty. For a fixture that sets up its own schema,
// roles or partial migrations: open every connection of that fixture with the
// returned URL instead of base, and its schema no longer shares a database
// with sibling schemas (see FreshSchemaPool for why that matters).
func FreshDatabaseURL(t testing.TB, base, prefix string) string {
	t.Helper()
	config, _ := freshDatabase(t, base, prefix)
	return config.ConnString()
}

// freshDatabase creates the database and returns a pool config pointed at it
// (ConnString is the rewritten URL) and its name.
func freshDatabase(t testing.TB, base, prefix string) (*pgxpool.Config, string) {
	t.Helper()
	if !templateName.MatchString(prefix) || len(prefix) > 30 {
		t.Fatalf("unsafe database prefix %q", prefix)
	}
	base = strings.TrimSpace(base)
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := prefix + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" TEMPLATE template0"); err != nil {
		_ = admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dropCtx, dropCancel := CleanupContext()
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, "DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)"); err != nil {
			t.Logf("drop test database %s (left behind): %v", name, err)
		}
		_ = admin.Close(dropCtx)
	})
	url, err := WithDatabase(base, name)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	return config, name
}

// WithDatabase returns the connection string base with its database replaced.
func WithDatabase(base, name string) (string, error) {
	if !strings.Contains(base, "://") {
		// keyword/value form: a later dbname overrides an earlier one.
		return base + " dbname=" + name, nil
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	parsed.Path = "/" + name
	parsed.RawPath = ""
	return parsed.String(), nil
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
