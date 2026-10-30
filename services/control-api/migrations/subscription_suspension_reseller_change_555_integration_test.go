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

// Migration 555 rolls back cleanly while no suspension or reseller change fact
// exists and applies again: the suspension columns, the suspend/unsuspend
// version operation, the wholesale helper and the P5555 refund guard come and
// go together.
func TestSubscriptionSuspensionResellerChange555UpDownUp(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "mig555_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	type state struct{ column, helper, guard, operation bool }
	read := func() state {
		t.Helper()
		var s state
		if err := pool.QueryRow(t.Context(), `SELECT
			EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=$1
				AND table_name='package_subscriptions' AND column_name='suspended_at'),
			EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
				WHERE n.nspname=$1 AND p.proname='reseller_change_wholesale_555'),
			EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
				WHERE n.nspname=$1 AND p.proname='assert_reseller_transaction_483' AND p.prosrc LIKE '%P5555%'),
			EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
				WHERE n.nspname=$1 AND c.conname='package_subscription_versions_operation_check'
				AND pg_get_constraintdef(c.oid) LIKE '%unsuspend%')`, schema).
			Scan(&s.column, &s.helper, &s.guard, &s.operation); err != nil {
			t.Fatal(err)
		}
		return s
	}
	applied := state{true, true, true, true}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 555); err != nil || read() != applied {
		t.Fatalf("up: %v state=%+v", err, read())
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 555); err != nil || read() != (state{}) {
		t.Fatalf("down: %v state=%+v", err, read())
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 555); err != nil || read() != applied {
		t.Fatalf("up again: %v state=%+v", err, read())
	}
}
