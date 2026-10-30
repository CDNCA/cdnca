//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestAdminSelfApproval435: up/down/up. control_platform_admin_435 is true only
// for an active user holding platform.admin through a role in an active
// platform membership (in the given scope when one is named).
func TestAdminSelfApproval435(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_admin_self_approval.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("admin self approval migration: %v %v", matches, err)
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

	platformScope, tenantID, tenantScope := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'self approval tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenantID)
	seed := func(scopeID uuid.UUID, permission string) uuid.UUID {
		t.Helper()
		userID, roleID := uuid.New(), uuid.New()
		mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status)
			VALUES($1,$2,'self approval','not-used','active')`, userID, "self-"+userID.String()[:18])
		mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, scopeID, userID)
		mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,$3,true)`, roleID, scopeID, "self_"+roleID.String()[:18])
		mustExec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		mustExec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID)
		return userID
	}
	admin := seed(platformScope, "platform.admin")
	approver := seed(platformScope, "billing.adjustments.approve")
	// A tenant role cannot hold platform.admin at all (042/084 role guard);
	// the tenant member holds a tenant permission instead.
	tenantAdmin := seed(tenantScope, "sites.read")
	check := func(name string, userID uuid.UUID, scopeID *uuid.UUID, want bool) {
		t.Helper()
		var got bool
		if err := pool.QueryRow(ctx, `SELECT control_platform_admin_435($1,$2)`, userID, scopeID).Scan(&got); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
	check("platform administrator", admin, &platformScope, true)
	check("platform administrator, any scope", admin, nil, true)
	check("platform administrator, other scope", admin, &tenantScope, false)
	check("approver without platform.admin", approver, &platformScope, false)
	check("tenant member", tenantAdmin, nil, false)
	mustExec(t, pool, `UPDATE memberships SET status='suspended' WHERE user_id=$1`, admin)
	check("suspended platform administrator", admin, nil, false)

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regprocedure('control_platform_admin_435(uuid,uuid)') IS NOT NULL`).
		Scan(&exists); err != nil || exists {
		t.Fatalf("control_platform_admin_435 kept after down: %v %v", exists, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
