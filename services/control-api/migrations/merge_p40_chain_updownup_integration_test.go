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

// 1.0.35: renumbered on merge — fw-default 607→605,
// autodefense-ux 608→606, fw-receipt 609→607, node-ssh-tab 610→608; merge-p40b smartsched-core 611→609. 605–609
// must each apply on their exact predecessor, roll back one step and apply again.
func TestMergeP40ChainUpDownUp605To609(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig_p40_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	head := func() int64 {
		t.Helper()
		var version int64
		if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		return version
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 604); err != nil || head() != 604 {
		t.Fatalf("up to 604: %v", err)
	}
	for version := int64(605); version <= 609; version++ {
		if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil || head() != version {
			t.Fatalf("up %d: %v", version, err)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil || head() != version-1 {
			t.Fatalf("down %d: %v (head %d)", version, err, head())
		}
		if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil || head() != version {
			t.Fatalf("up again %d: %v", version, err)
		}
	}
}
