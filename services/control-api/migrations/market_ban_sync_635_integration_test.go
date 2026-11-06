//go:build integration

package migrations_test

import (
	"testing"
)

// Migration 635 drops the ban sync tables and the market
// source on down and applies again.
func TestMarketBanSync635UpDownUp(t *testing.T) {
	const version = 635
	pool := migrationPoolAt(t, version)
	state := func() (bool, bool) {
		t.Helper()
		var tables, market bool
		if err := pool.QueryRow(t.Context(), `SELECT
				to_regclass('market_supply_ban_refs') IS NOT NULL AND to_regclass('market_supply_ban_sites') IS NOT NULL
				AND to_regclass('site_supply_ban_deliveries') IS NOT NULL,
				EXISTS (SELECT 1 FROM pg_constraint WHERE conname='security_ban_entries_source_635'
					AND pg_get_constraintdef(oid) LIKE '%market%')`).Scan(&tables, &market); err != nil {
			t.Fatal(err)
		}
		return tables, market
	}
	if tables, market := state(); !tables || !market {
		t.Fatalf("at head: tables=%v market=%v", tables, market)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if tables, market := state(); tables || market {
		t.Fatalf("after down: tables=%v market=%v", tables, market)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if tables, market := state(); !tables || !market {
		t.Fatalf("after up: tables=%v market=%v", tables, market)
	}
}
