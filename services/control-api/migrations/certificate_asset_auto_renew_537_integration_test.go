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

// Migration 537 rolls back cleanly while no auto-renew change was made and
// applies again.
func TestCertificateAssetAutoRenew537UpDownUp(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig537_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
			WHERE table_schema=$1 AND table_name='certificate_assets' AND column_name='auto_renew')`, schema).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 537); err != nil || !column() {
		t.Fatalf("up: %v column=%v", err, column())
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 537); err != nil || column() {
		t.Fatalf("down: %v column=%v", err, column())
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 537); err != nil || !column() {
		t.Fatalf("up again: %v column=%v", err, column())
	}
}
