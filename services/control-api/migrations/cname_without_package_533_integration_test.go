//go:build integration

package migrations_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 533 rolls back cleanly on a database without package-less CNAME
// facts and applies again.
func TestCNAMEWithoutPackage533UpDownUp(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig533_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
			WHERE table_schema=$1 AND table_name='node_line_groups' AND column_name='is_platform_default')`, schema).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil || !column() {
		t.Fatalf("up: %v column=%v", err, column())
	}
	// Later migrations (534+) roll back first so the next down is 533's.
	for {
		var head int
		if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil {
			t.Fatal(err)
		}
		if head <= 533 {
			break
		}
		if err := database.Migrate(t.Context(), pool, "down"); err != nil {
			t.Fatalf("down from %d: %v", head, err)
		}
	}
	if err := database.Migrate(t.Context(), pool, "down"); err != nil || column() {
		t.Fatalf("down: %v column=%v", err, column())
	}
	var nullable string
	if err := pool.QueryRow(t.Context(), `SELECT is_nullable FROM information_schema.columns WHERE table_schema=$1
		AND table_name='cname_allocation_intents' AND column_name='package_subscription_id'`, schema).Scan(&nullable); err != nil || nullable != "NO" {
		t.Fatalf("intent package_subscription_id nullable=%s err=%v", nullable, err)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil || !column() {
		t.Fatalf("up again: %v column=%v", err, column())
	}
}
