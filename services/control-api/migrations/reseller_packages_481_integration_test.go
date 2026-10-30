//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestResellerPackages481 rolls 481 up with a platform package already in the
// catalog (it is filed under the platform scope), down and up, then checks
// the owner guards of ADR 0018 RS-02: owner is the platform or an active
// reseller (P4813) and immutable (P4814); names are unique per owner; and the
// revocation lookup now finds a reseller package by its main/backup line.
func TestResellerPackages481(t *testing.T) {
	const version = 481
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	user, legacy, agent, plain, line := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var platform uuid.UUID
	exec := func(tx pgx.Tx, sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("%s: %v", sql, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec(tx, `SET LOCAL session_replication_role = replica`)
	exec(tx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'rs','hash')`, user, "rs-481-"+user.String())
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
		exec(tx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	} else if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []uuid.UUID{agent, plain} {
		tenant := uuid.New()
		exec(tx, `INSERT INTO tenants(id,display_name) VALUES($1,'rs 481')`, tenant)
		exec(tx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	}
	exec(tx, `INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,updated_by_user_id,updated_at)
		VALUES($1,'active',1,$2,$3,$2,$3)`, agent, user, now)
	exec(tx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
		created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
		VALUES($1::uuid,$2,'rs481',1,$3,$3,$4,$4,48100,'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
		line, platform, user, now)
	exec(tx, `INSERT INTO package_products(id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,'同名',true,1,'{"group_ids":[]}'::jsonb,1,$2,$2,$3,$3)`, legacy, user, now)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT owner_scope_id FROM package_products WHERE id=$1`, legacy).Scan(&owner); err != nil || owner != platform {
		t.Fatalf("existing package owner = %s, %v", owner, err)
	}
	for _, step := range []string{"down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	// probe runs one catalog write and rolls it back: the 481 BEFORE guards
	// answer immediately (the 090 audit chain would refuse a bare row at
	// commit). keep writes the row in replica mode (no triggers) instead.
	probe := func(sql string, args ...any) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, sql, args...)
		return err
	}
	const insertProduct = `INSERT INTO package_products(id,owner_scope_id,name,enabled,sort_order,spec,revision,
		created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,false,1,$4::jsonb,1,$5,$5,$6,$6)`
	insert := func(owner uuid.UUID, name, spec string) error {
		return probe(insertProduct, uuid.New(), owner, name, spec, user, now)
	}
	keep := func(owner uuid.UUID, name, spec string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		exec(tx, `SET LOCAL session_replication_role = replica`)
		exec(tx, insertProduct, uuid.New(), owner, name, spec, user, now)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}
	// A plain tenant cannot own packages; a reseller can, under a name the platform already uses.
	if err := insert(plain, "普通租户", `{"group_ids":[]}`); code(err) != "P4813" {
		t.Fatalf("plain tenant owner = %v", err)
	}
	if err := insert(agent, "同名", `{"group_ids":[]}`); code(err) == "23505" || code(err) == "P4813" {
		t.Fatalf("reseller package with a platform name: %v", err)
	}
	keep(agent, "同名", `{"group_ids":[],"node_group_id":"`+line.String()+`"}`)
	if err := insert(agent, "同名", `{"group_ids":[]}`); code(err) != "23505" {
		t.Fatalf("duplicate name within one owner = %v", err)
	}
	if err := probe(`UPDATE package_products SET owner_scope_id=$2 WHERE id=$1`, legacy, agent); code(err) != "P4814" {
		t.Fatalf("owner change = %v", err)
	}
	// Revocation lookup: the reseller package whose main line is the group.
	var found int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM reseller_products_using_line_group_480($1,$2,$3)`, agent, platform, line).
		Scan(&found); err != nil || found != 1 {
		t.Fatalf("reseller packages using the line = %d, %v", found, err)
	}
	// Down refuses to fold reseller packages into the platform catalog.
	if err := migrateVersionIsolated(ctx, pool, "down", version); code(errors.Unwrap(err)) != "P4818" && code(err) != "P4818" {
		t.Fatalf("down with reseller packages = %v", err)
	}
}
