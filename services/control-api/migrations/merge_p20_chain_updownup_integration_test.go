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

// 1.0.35 renumbered migrations 555–574 on merge; every one of
// them must still apply on its exact predecessor, roll back one step and apply
// again. One schema walks the chain: up to N, down (head N-1), up to N again.
func TestMergeP20ChainUpDownUp555To574(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig_p20_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	if err := migrateVersionIsolated(t.Context(), pool, "up", 554); err != nil || head() != 554 {
		t.Fatalf("up to 554: %v", err)
	}
	for version := int64(555); version <= 574; version++ {
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
