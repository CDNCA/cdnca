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

// TestSiteServerTiming651UpDownUp rolls
// sites.server_timing up, down and up again on the 650 head: boolean NOT NULL
// DEFAULT false (existing sites stay off); down removes it.
func TestSiteServerTiming651UpDownUp(t *testing.T) {
	const version = 651
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	shape := func() string {
		t.Helper()
		var found string
		err := pool.QueryRow(ctx, `SELECT COALESCE(max(udt_name || ' ' || is_nullable || ' ' || COALESCE(column_default,'')),'')
			FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='sites' AND column_name='server_timing'`).Scan(&found)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	for _, step := range []struct {
		direction, want string
	}{{"up", "bool NO false"}, {"down", ""}, {"up", "bool NO false"}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := shape(); got != step.want {
			t.Fatalf("after %s sites.server_timing = %q, want %q", step.direction, got, step.want)
		}
	}
}

// 651 sites.server_timing on top of 650. 650 and 651 must each apply on their
// exact predecessor, roll back one step and apply again, in chain order.
func TestSiteServerTimingChainUpDownUp650To651(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig_server_timing_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	if err := migrateVersionIsolated(t.Context(), pool, "up", 650); err != nil || head() != 650 {
		t.Fatalf("up to 650: %v", err)
	}
	for version := int64(650); version <= 651; version++ {
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
