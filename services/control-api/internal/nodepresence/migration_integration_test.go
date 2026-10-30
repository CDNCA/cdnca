//go:build integration

package nodepresence

import (
	"context"
	"os"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAgentVersionMigrationRoundTrip(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, adminPool, schema := openPresenceTestDatabase(t, databaseURL)
	defer pool.Close()
	defer adminPool.Close()
	defer func() {
		if _, err := adminPool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop migration test schema: %v", err)
		}
	}()
	// 迁移 268 的 down 是刻意的单向闸门，不能从发布头回滚；这里只装载 1..roundTripHead，
	// 验证 014/018 的往返，再用完整迁移前滚到发布头。
	const roundTripHead = 20
	if err := databasetest.MigrateThrough(ctx, pool, "up", roundTripHead); err != nil {
		t.Fatal(err)
	}
	for currentMigrationVersion(t, pool) > 17 {
		if err := databasetest.MigrateThrough(ctx, pool, "down", roundTripHead); err != nil {
			t.Fatal(err)
		}
	}
	assertAgentVersionColumn(t, pool, true)
	if err := databasetest.MigrateThrough(ctx, pool, "down", roundTripHead); err != nil {
		t.Fatal(err)
	}
	assertAgentVersionColumn(t, pool, false)
	assertNodePresenceTable(t, pool, true)
	for currentMigrationVersion(t, pool) > 14 {
		if err := databasetest.MigrateThrough(ctx, pool, "down", roundTripHead); err != nil {
			t.Fatal(err)
		}
	}
	assertNodePresenceTable(t, pool, false)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	assertNodePresenceTable(t, pool, true)
	assertAgentVersionColumn(t, pool, true)
}

func currentMigrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func assertNodePresenceTable(t *testing.T, pool *pgxpool.Pool, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('node_presence') IS NOT NULL`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("node_presence table exists = %t, want %t", actual, expected)
	}
}

func assertAgentVersionColumn(t *testing.T, pool *pgxpool.Pool, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = 'node_presence' AND column_name = 'agent_version'
		)`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("agent_version column exists = %t, want %t", actual, expected)
	}
}
