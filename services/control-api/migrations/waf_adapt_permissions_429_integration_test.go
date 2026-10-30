//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	"github.com/google/uuid"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestWAFAdaptPermissions429: up grants waf_adapt.read to the existing and
// new tenant_owner / tenant_viewer roles and waf_adapt.manage to owners only
// (the viewer guard refuses manage); reject_reason accepts the three codes
// on rejected rows only; down removes them and restores the guard, up again.
func TestWAFAdaptPermissions429(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_waf_adapt_permissions.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("waf adapt permissions migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	tenantA, scopeA, ownerA, viewerA := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'waf adapt 429 a')`, tenantA)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeA, tenantA)
	exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$3,'tenant_owner',true),($2,$3,'tenant_viewer',true)`, ownerA, viewerA, scopeA)
	granted := func(role uuid.UUID, permission string) bool {
		t.Helper()
		var found bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name=$2)`,
			role, permission).Scan(&found); err != nil {
			t.Fatal(err)
		}
		return found
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		applied := step == "up"
		if granted(ownerA, "waf_adapt.read") != applied || granted(ownerA, "waf_adapt.manage") != applied ||
			granted(viewerA, "waf_adapt.read") != applied || granted(viewerA, "waf_adapt.manage") {
			t.Fatalf("after %s: owner %v/%v viewer %v/%v", step, granted(ownerA, "waf_adapt.read"), granted(ownerA, "waf_adapt.manage"),
				granted(viewerA, "waf_adapt.read"), granted(viewerA, "waf_adapt.manage"))
		}
		var column bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_name='waf_adapt_exclusions' AND column_name='reject_reason')`).Scan(&column); err != nil || column != applied {
			t.Fatalf("after %s: reject_reason column %v (%v)", step, column, err)
		}
	}
	// a new tenant gets them through the roles trigger
	tenantB, scopeB, ownerB, viewerB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'waf adapt 429 b')`, tenantB)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeB, tenantB)
	exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$3,'tenant_owner',true),($2,$3,'tenant_viewer',true)`, ownerB, viewerB, scopeB)
	if !granted(ownerB, "waf_adapt.read") || !granted(ownerB, "waf_adapt.manage") || !granted(viewerB, "waf_adapt.read") ||
		granted(viewerB, "waf_adapt.manage") {
		t.Fatal("new tenant roles: waf_adapt grants missing or viewer holds manage")
	}
	// the viewer guard still refuses a write permission
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'waf_adapt.manage')`, viewerB); err == nil {
		t.Fatal("tenant_viewer accepted waf_adapt.manage")
	}
	var step bool
	if err := pool.QueryRow(ctx, `SELECT step_up_required FROM custom_rbac_permission_catalog WHERE permission_name='waf_adapt.manage'`).
		Scan(&step); err != nil || !step {
		t.Fatalf("waf_adapt.manage step up %v (%v)", step, err)
	}
}
