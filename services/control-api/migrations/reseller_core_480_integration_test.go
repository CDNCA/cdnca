//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestResellerCore480 rolls 480 up, down and up, then checks the guards of
// ADR 0018 RS-01: a line group grant needs an active reseller grantee
// (P4801), no may_regrant (P4802), the platform owner as grantor (P4803);
// a parent must be an active reseller (P4804), not the tenant itself
// (P4805), a reseller has no parent (P4806), the customer limit holds
// (P4808); opening a reseller grants the reseller.* permissions to its
// tenant_owner and suspending takes them away.
func TestResellerCore480(t *testing.T) {
	const version = 480
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	user := uuid.New()
	var platform uuid.UUID
	agent, other, customer := uuid.New(), uuid.New(), uuid.New()
	tenantOf := map[uuid.UUID]uuid.UUID{agent: uuid.New(), other: uuid.New(), customer: uuid.New()}
	ownerRole := uuid.New()
	group := uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(tx pgx.Tx, sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(tx, `SET LOCAL session_replication_role = replica`)
	exec(tx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'rs','hash')`, user, "rs-480-"+user.String())
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err == pgx.ErrNoRows {
		platform = uuid.New()
		exec(tx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	} else if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []uuid.UUID{agent, other, customer} {
		exec(tx, `INSERT INTO tenants(id,display_name) VALUES($1,'rs 480')`, tenantOf[scope])
		exec(tx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenantOf[scope])
	}
	exec(tx, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,'tenant_owner','owner',true,$3)`,
		ownerRole, agent, now)
	exec(tx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
		created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
		VALUES($1::uuid,$2,$3,1,$4,$4,$5,$5,48000,'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
		group, platform, "rs-480-"+group.String()[:8], user, now)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	grant := func(grantor, grantee uuid.UUID, regrant bool) error {
		_, err := pool.Exec(ctx, `INSERT INTO node_line_group_grants(id,owner_scope_id,line_group_id,grantor_scope_id,
			grantee_scope_id,may_regrant,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			uuid.New(), platform, group, grantor, grantee, regrant, user, now)
		return err
	}
	profile := func(scope uuid.UUID, status string, limit any) error {
		var suspended any
		if status == "suspended" {
			suspended = now
		}
		_, err := pool.Exec(ctx, `INSERT INTO reseller_profiles(scope_id,status,customer_limit,revision,created_by_user_id,
			created_at,updated_by_user_id,updated_at,suspended_at) VALUES($1,$2,$3,1,$4,$5,$4,$5,$6)`,
			scope, status, limit, user, now, suspended)
		return err
	}
	parent := func(scope uuid.UUID, to any) error {
		_, err := pool.Exec(ctx, `UPDATE tenants SET parent_scope_id=$2 WHERE id=$1`, tenantOf[scope], to)
		return err
	}
	resellerPermissions := func() int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions WHERE role_id=$1 AND permission_name LIKE 'reseller.%'`,
			ownerRole).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Repro: before 480 any tenant could be a grantee (EscalateLineGroupsPanel listed all tenants).
	if err := grant(platform, agent, false); sqlState(err) != "P4801" {
		t.Fatalf("grant to an ordinary tenant: %v, want P4801", err)
	}
	if err := profile(agent, "active", 1); err != nil {
		t.Fatalf("open reseller: %v", err)
	}
	if n := resellerPermissions(); n != 3 {
		t.Fatalf("reseller permissions after opening = %d, want 3", n)
	}
	// The platform owner role may hold them too (bootstrap grants the platform every permission).
	var platformRole uuid.UUID
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
		SELECT $1,$2,'platform_owner','owner',true,$3 WHERE NOT EXISTS (SELECT 1 FROM roles WHERE scope_id=$2 AND name='platform_owner')`,
		uuid.New(), platform, now)
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name='platform_owner'`, platform).Scan(&platformRole); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'reseller.customers.read')
		ON CONFLICT DO NOTHING`, platformRole); err != nil {
		t.Fatalf("platform owner holds reseller permissions: %v", err)
	}
	if err := grant(platform, agent, true); sqlState(err) != "P4802" {
		t.Fatalf("may_regrant: %v, want P4802", err)
	}
	// A grantor that is not the owner is refused by 460 first (P4603; 480's P4803 backs it).
	if err := grant(other, agent, false); sqlState(err) != "P4603" {
		t.Fatalf("grantor not the owner: %v, want P4603", err)
	}
	if err := grant(platform, agent, false); err != nil {
		t.Fatalf("grant to a reseller: %v", err)
	}

	if err := parent(customer, other); sqlState(err) != "P4804" {
		t.Fatalf("parent not a reseller: %v, want P4804", err)
	}
	if err := parent(agent, agent); sqlState(err) != "P4805" {
		t.Fatalf("own parent: %v, want P4805", err)
	}
	if err := parent(customer, agent); err != nil {
		t.Fatalf("customer under reseller: %v", err)
	}
	if err := parent(other, agent); sqlState(err) != "P4808" {
		t.Fatalf("over the customer limit: %v, want P4808", err)
	}
	// A reseller's customer cannot become a reseller; a reseller cannot get a parent.
	if err := profile(customer, "active", nil); sqlState(err) != "P4806" {
		t.Fatalf("customer becomes a reseller: %v, want P4806", err)
	}
	if err := profile(other, "active", nil); err != nil {
		t.Fatal(err)
	}
	if err := parent(other, agent); sqlState(err) != "P4806" {
		t.Fatalf("reseller under a reseller: %v, want P4806", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM reseller_profiles WHERE scope_id=$1`, other); sqlState(err) != "P4807" {
		t.Fatalf("delete profile: %v, want P4807", err)
	}

	// Suspending takes the permissions away; a suspended reseller gets no new grants or customers.
	if _, err := pool.Exec(ctx, `UPDATE reseller_profiles SET status='suspended',suspended_at=$2,revision=revision+1
		WHERE scope_id=$1`, agent, now); err != nil {
		t.Fatal(err)
	}
	if n := resellerPermissions(); n != 0 {
		t.Fatalf("reseller permissions after suspension = %d, want 0", n)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'reseller.customers.read')`,
		ownerRole); sqlState(err) != "P4801" {
		t.Fatalf("reseller permission on a suspended reseller: %v, want P4801", err)
	}
	if err := parent(customer, nil); err != nil {
		t.Fatalf("back to the platform: %v", err)
	}
	if err := parent(customer, agent); sqlState(err) != "P4804" {
		t.Fatalf("customer under a suspended reseller: %v, want P4804", err)
	}

	// Down refuses while resellers exist.
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4811" {
		t.Fatalf("down with resellers: %v, want P4811", err)
	}
}
