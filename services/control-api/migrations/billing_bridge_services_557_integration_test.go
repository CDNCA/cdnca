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

// Migration 557 rolls back cleanly while no service or client mapping exists
// and applies again: the five billing bridge facade tables and their guard
// functions come and go together.
func TestBillingBridgeServices557UpDownUp(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig557_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	objects := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM information_schema.tables WHERE table_schema=$1 AND table_name IN
				('billing_bridge_clients','billing_bridge_services','billing_bridge_requests',
				 'billing_bridge_sso_tickets','billing_bridge_settings')) +
			(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND
				p.proname IN ('guard_billing_bridge_service_557','guard_billing_bridge_sso_ticket_557'))`,
			schema).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 557); err != nil || objects() != 7 {
		t.Fatalf("up: %v objects=%d", err, objects())
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 557); err != nil || objects() != 0 {
		t.Fatalf("down: %v objects=%d", err, objects())
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 557); err != nil || objects() != 7 {
		t.Fatalf("up again: %v objects=%d", err, objects())
	}
}
