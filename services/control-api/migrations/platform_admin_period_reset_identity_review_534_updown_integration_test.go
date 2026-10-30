//go:build integration

package migrations_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 534 rolls back cleanly while no platform administrator facts
// exist and applies again.
func TestPlatformAdminPeriodResetIdentityReview534UpDownUp(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig534_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	column := func() bool {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema=$1 AND table_name='package_period_reset_workload_authority_bindings_165' AND column_name='actor_scope_id')`, schema).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 534); err != nil || !column() {
		t.Fatalf("up: %v column=%v", err, column())
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 534); err != nil || column() {
		t.Fatalf("down: %v column=%v", err, column())
	}
	var fkCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_constraint WHERE contype='f'
		AND connamespace=$1::regnamespace AND confrelid=($1||'.memberships')::regclass
		AND conrelid::regclass::text LIKE '%identity_verification_%' AND pg_get_constraintdef(oid) LIKE '%reviewer_user_id%'`,
		schema).Scan(&fkCount); err != nil || fkCount != 3 {
		t.Fatalf("down restored reviewer membership FKs=%d err=%v, want 3", fkCount, err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 534); err != nil || !column() {
		t.Fatalf("up again: %v column=%v", err, column())
	}
}
