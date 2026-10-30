//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestMarketSupplyLineGroups427 rolls 427 up, down and up, then checks that
// purpose defaults to general, is fixed at creation, that a supply group must
// belong to the platform scope, and that down refuses while one exists.
func TestMarketSupplyLineGroups427(t *testing.T) {
	const version = 427
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	platform, tenant, tenantID, user := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'t427')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenant, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ml09-427','ML09','unused')`, user)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$3),($2,$3)`, platform, tenant, user)
	const insert = `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
		updated_by_user_id,created_at,updated_at,purpose) VALUES($1,$2,$3,1,$4,$4,now(),now(),$5)`

	// BEFORE triggers run at the statement; the deferred snapshot check never
	// fires because each transaction is rolled back.
	inTx := func(check func(tx pgx.Tx)) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		check(tx)
	}
	inTx(func(tx pgx.Tx) {
		id := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,'g-general',1,$3,$3,now(),now())`, id, platform, user); err != nil {
			t.Fatalf("insert general: %v", err)
		}
		var purpose string
		if err := tx.QueryRow(ctx, `SELECT purpose FROM node_line_groups WHERE id=$1`, id).Scan(&purpose); err != nil || purpose != "general" {
			t.Fatalf("default purpose %q, %v", purpose, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE node_line_groups SET purpose='market_supply',current_revision=2 WHERE id=$1`, id); sqlState(err) != "P4271" {
			t.Fatalf("purpose change: %v, want P4271", err)
		}
	})
	inTx(func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, insert, uuid.New(), tenant, "g-tenant", user, "market_supply"); sqlState(err) != "P4272" {
			t.Fatalf("tenant supply group: %v, want P4272", err)
		}
	})
	inTx(func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, insert, uuid.New(), platform, "g-bad", user, "other"); sqlState(err) != "23514" {
			t.Fatalf("unknown purpose: %v, want 23514", err)
		}
	})
	// A committed supply group (triggers off: only the down fence is tested).
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,
		updated_by_user_id,created_at,updated_at,purpose,display_id,resolved_value,ipv4_resolved_value)
		VALUES($1,$2,'g-supply',1,$3,$3,now(),now(),'market_supply',1,'lg-427supply','v4-427supply')`, uuid.New(), platform, user); err != nil {
		t.Fatalf("seed supply group: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4274" {
		t.Fatalf("down with a supply group: %v, want P4274", err)
	}
}
