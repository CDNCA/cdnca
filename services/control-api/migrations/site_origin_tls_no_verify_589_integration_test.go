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

// Migration 589 up/down/up: the tls_trust check accepts 'none' only while
// applied.
func TestSiteOriginTLSNoVerify589UpDownUp(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig589_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	allowsNone := func() bool {
		t.Helper()
		var allowed bool
		if err := pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(c.oid) LIKE '%none%'
			FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
			WHERE n.nspname=$1 AND c.conname='site_origin_pools_tls_trust_check'`, schema).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		return allowed
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 589); err != nil || !allowsNone() {
		t.Fatalf("up: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 589); err != nil || allowsNone() {
		t.Fatalf("down: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 589); err != nil || !allowsNone() {
		t.Fatalf("up again: %v", err)
	}
}
