//go:build integration

package nodeidentity

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNodeIdentityMigrationRoundTrip(t *testing.T) {
	pool := openIdentityTestDatabase(t, false)
	ctx := context.Background()
	// 268 的 down 是刻意的单向闸门，不能从发布头回滚；往返只装载 1..21。
	if err := databasetest.MigrateThrough(ctx, pool, "up", 21); err != nil {
		t.Fatal(err)
	}
	assertIdentityMigrationApplied(t, pool, 21)
	for _, table := range []string{"node_identity_state", "node_identity_authorizations", "node_artifact_encryption_keys",
		"node_certificate_renewal_requests", "node_certificates", "node_certificate_revocations", "node_certificate_events"} {
		assertIdentityTable(t, pool, table, true)
	}
	migrateIdentityDownToVersion(t, pool, 20)
	assertIdentityTable(t, pool, "node_identity_authorizations", true)
	migrateIdentityDownToVersion(t, pool, 19)
	assertIdentityTable(t, pool, "node_identity_authorizations", true)
	migrateIdentityDownToVersion(t, pool, 18)
	assertIdentityTable(t, pool, "node_identity_authorizations", false)
	assertIdentityTable(t, pool, "node_enrollment_authorizations", true)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	assertIdentityMigrationApplied(t, pool, 21)
	assertIdentityTable(t, pool, "node_certificates", true)
}

func openIdentityTestDatabase(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "node_identity_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^node_identity_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop identity schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func identityMigrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func assertIdentityMigrationApplied(t *testing.T, pool *pgxpool.Pool, version int64) {
	t.Helper()
	var applied bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatalf("identity migration %d is not applied", version)
	}
}

func migrateIdentityDownToVersion(t *testing.T, pool *pgxpool.Pool, target int64) {
	t.Helper()
	current := identityMigrationVersion(t, pool)
	if current < target {
		t.Fatalf("cannot migrate down from version %d to %d", current, target)
	}
	for current > target {
		if err := databasetest.MigrateThrough(context.Background(), pool, "down", 21); err != nil {
			t.Fatalf("migrate down from version %d: %v", current, err)
		}
		next := identityMigrationVersion(t, pool)
		if next >= current {
			t.Fatalf("migration down did not advance: before=%d after=%d", current, next)
		}
		current = next
	}
	if current != target {
		t.Fatalf("migration version = %d, want %d", current, target)
	}
}

func assertIdentityTable(t *testing.T, pool *pgxpool.Pool, table string, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("table %s exists = %t, want %t", table, actual, expected)
	}
}
