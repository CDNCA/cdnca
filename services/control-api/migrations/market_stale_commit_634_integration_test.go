//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
)

// Migration 634 (local placeholder) rolls back to the 095 recovery predicate
// and drops the leaf revision table, and applies again.
func TestMarketStaleCommit634UpDownUp(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	state := func() (bool, bool) {
		t.Helper()
		var table bool
		var body string
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass('market_supply_site_revisions') IS NOT NULL,
			prosrc FROM pg_proc WHERE proname='security_policy_activation_recovered_095'
			AND pronamespace=current_schema()::regnamespace`).Scan(&table, &body); err != nil {
			t.Fatal(err)
		}
		return table, strings.Contains(body, "newer.created_at > deployment.created_at")
	}
	if table, extended := state(); !table || !extended {
		t.Fatalf("at head: table=%v extended=%v", table, extended)
	}
	if err := database.Migrate(t.Context(), pool, "down"); err != nil {
		t.Fatalf("down: %v", err)
	}
	if table, extended := state(); table || extended {
		t.Fatalf("after down: table=%v extended=%v", table, extended)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if table, extended := state(); !table || !extended {
		t.Fatalf("after up: table=%v extended=%v", table, extended)
	}
}
