//go:build integration

package migrations_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDNSRecordsManage603 (plugapi-S1): 603 up grants dns.records.manage to
// every tenant system role holding dns.manage (not tenant_viewer), a new
// tenant_owner gets it through the trigger; down refuses (P6032) while an
// API key holds it, and after the key is gone it removes exactly the grants
// and the permission; up again restores them.
func TestDNSRecordsManage603(t *testing.T) {
	// Keep equal to the 603 contract's version.
	const version = 603
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	ownerRole, viewerRole := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'603 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'dnsrecords-603','DNS 603','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$3,'tenant_owner',true),($2,$3,'tenant_viewer',true)`,
		ownerRole, viewerRole, scopeID)
	mustExec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'dns.read'),($1,'dns.manage'),($2,'dns.read')`,
		ownerRole, viewerRole)

	holds := func(role uuid.UUID) bool {
		t.Helper()
		var held bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name='dns.records.manage')`,
			role).Scan(&held); err != nil {
			t.Fatal(err)
		}
		return held
	}
	permissionExists := func() bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM permissions WHERE name='dns.records.manage')
			AND EXISTS(SELECT 1 FROM custom_rbac_permission_catalog WHERE permission_name='dns.records.manage')`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if !permissionExists() || !holds(ownerRole) || holds(viewerRole) {
		t.Fatalf("after up: permission=%v owner=%v viewer=%v", permissionExists(), holds(ownerRole), holds(viewerRole))
	}
	// A tenant created after 603 gets it on its tenant_owner (trigger).
	laterTenant, laterScope, laterOwner := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'603 later')`, laterTenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, laterScope, laterTenant)
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'tenant_owner',true)`, laterOwner, laterScope)
	// Like every real tenant_owner it also holds dns.manage (the up backfill keys on it).
	mustExec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'dns.manage')`, laterOwner)
	if !holds(laterOwner) {
		t.Fatal("new tenant_owner lacks dns.records.manage")
	}

	// Down refuses while an API key holds the permission.
	keyID := uuid.New()
	insertKey603(t, pool, keyID, scopeID, tenantID, userID)
	err := migrateVersionIsolated(ctx, pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P6032" {
		t.Fatalf("down with an API key holding dns.records.manage = %v, want P6032", err)
	}
	if !permissionExists() || !holds(ownerRole) {
		t.Fatal("refused down changed the grants")
	}
	// api_keys forbids DELETE (lifecycle guard); the fixture key goes with
	// its guard off, only to let the second down run.
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM api_keys WHERE id=$1`, keyID)
		return err
	}); err != nil {
		t.Fatalf("drop fixture key: %v", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if permissionExists() || holds(ownerRole) || holds(laterOwner) {
		t.Fatalf("after down: permission=%v owner=%v later=%v", permissionExists(), holds(ownerRole), holds(laterOwner))
	}
	var manageKept bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name='dns.manage')`,
		ownerRole).Scan(&manageKept); err != nil || !manageKept {
		t.Fatalf("down removed dns.manage: %v %v", manageKept, err)
	}

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again %d: %v", version, err)
	}
	if !holds(ownerRole) || !holds(laterOwner) || holds(viewerRole) {
		t.Fatalf("after up again: owner=%v later=%v viewer=%v", holds(ownerRole), holds(laterOwner), holds(viewerRole))
	}
}

// insertKey603 stores an active key scoped to dns.records.manage (the down
// guard reads api_keys.scopes only).
func insertKey603(t *testing.T, pool *pgxpool.Pool, id, scopeID, tenantID, userID uuid.UUID) {
	t.Helper()
	mustExec(t, pool, `INSERT INTO api_keys(id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,
		secret_digest,pepper_version,status,activated_at,created_by_user_id)
		VALUES($1,'cfk_DNSRECORDSMANAGE603AAA','cfk_DNSRECORDSMANAGE603AAA.',$2,$3,$4,'603 key',ARRAY['dns.records.manage'],
		$5,'legacy-v1','active',now(),$4)`, id, scopeID, tenantID, userID, bytes.Repeat([]byte{9}, 32))
}
