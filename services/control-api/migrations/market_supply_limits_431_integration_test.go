//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestMarketSupplyLimits431: up/down/up; the trigger market_limits is
// accepted only after up, a share row's checks hold, and a recorded
// market_limits republication blocks the rollback.
func TestMarketSupplyLimits431(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_market_supply_limits.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("market supply limits migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	for name, statement := range map[string]string{
		"bad key":            `INSERT INTO market_supply_limits(package_subscription_id,tenant_scope_id,market_key,node_pool_ref,serving_nodes,node_requests,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),'x','p',1,-1,now())`,
		"zero nodes":         `INSERT INTO market_supply_limits(package_subscription_id,tenant_scope_id,market_key,node_pool_ref,serving_nodes,node_requests,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),'0123456789abcdef01234567','p',0,-1,now())`,
		"throttle no bps":    `INSERT INTO market_supply_limits(package_subscription_id,tenant_scope_id,market_key,node_pool_ref,serving_nodes,node_requests,hold_action,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),'0123456789abcdef01234567','p',1,-1,'throttle',now())`,
		"requests too large": `INSERT INTO market_supply_limits(package_subscription_id,tenant_scope_id,market_key,node_pool_ref,serving_nodes,node_requests,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),'0123456789abcdef01234567','p',1,65536,now())`,
	} {
		if _, err := pool.Exec(ctx, statement); sqlState(err) != "23514" {
			t.Fatalf("%s: %v, want 23514", name, err)
		}
	}
	// The trigger is accepted by the republication checks after up ...
	var accepts bool
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) LIKE '%market_limits%' FROM pg_constraint
		WHERE conname='edge_system_revision_segments_source_check'`).Scan(&accepts); err != nil || !accepts {
		t.Fatalf("segment source check lacks market_limits: %v", err)
	}
	// ... and a share row blocks the rollback.
	mustExec(t, pool, `INSERT INTO market_supply_limits(package_subscription_id,tenant_scope_id,market_key,node_pool_ref,
		serving_nodes,node_requests,updated_at) SELECT id,tenant_scope_id,'0123456789abcdef01234567','p',1,-1,now()
		FROM package_subscriptions LIMIT 1`)
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM market_supply_limits`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows > 0 {
		if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4312" {
			t.Fatalf("down with a share row: %v, want P4312", err)
		}
		mustExec(t, pool, `DELETE FROM market_supply_limits`)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) LIKE '%market_limits%' FROM pg_constraint
		WHERE conname='edge_system_revision_segments_source_check'`).Scan(&accepts); err != nil || accepts {
		t.Fatalf("market_limits kept after down: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
