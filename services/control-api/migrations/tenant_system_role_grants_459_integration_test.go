//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestTenantSystemRoleGrants459（live-click-A E2 + fix-session E5）：up 给现有租户系统角色
// 回填 030/037/044/068/134 的权限，新建的租户系统角色经触发器同样获得；viewer 只拿
// 原迁移给它的三项；down 只撤本迁移新增的授权（迁移前已有的保留），再 up 恢复。
func TestTenantSystemRoleGrants459(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_tenant_system_role_grants.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("tenant system role grants migration: %v %v", matches, err)
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
	newTenant := func(name string) (owner, viewer uuid.UUID) {
		tenant, scope := uuid.New(), uuid.New()
		owner, viewer = uuid.New(), uuid.New()
		exec(`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenant, name)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
		exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$3,'tenant_owner',true),($2,$3,'tenant_viewer',true)`,
			owner, viewer, scope)
		return owner, viewer
	}
	granted := func(role uuid.UUID, permission string) bool {
		t.Helper()
		var found bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name=$2)`,
			role, permission).Scan(&found); err != nil {
			t.Fatal(err)
		}
		return found
	}
	ownerOnly := []string{"url_auth_policies.manage", "identity_verification.read", "identity_verification.review",
		"identity_verification.evidence_settlement.requeue", "promotions.quote", "promotions.redeem",
		"firewall.read", "firewall.manage"}
	shared := []string{"url_auth_policies.read", "identity_verification.self.manage", "promotions.read"}
	assertGrants := func(label string, owner, viewer uuid.UUID, want bool) {
		t.Helper()
		for _, permission := range append(append([]string{}, shared...), ownerOnly...) {
			if granted(owner, permission) != want {
				t.Errorf("%s: owner %s granted=%v, want %v", label, permission, !want, want)
			}
		}
		for _, permission := range shared {
			if granted(viewer, permission) != want {
				t.Errorf("%s: viewer %s granted=%v, want %v", label, permission, !want, want)
			}
		}
		for _, permission := range ownerOnly {
			if granted(viewer, permission) {
				t.Errorf("%s: viewer must not hold %s", label, permission)
			}
		}
	}

	// 迁移前新建的租户：复现缺陷（无触发器，一项都没有）
	ownerA, viewerA := newTenant("role grants 459 a")
	assertGrants("before up", ownerA, viewerA, false)
	// 迁移前已有的授权：down 不得撤掉
	exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'firewall.read')`, ownerA)

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		if step == "up" {
			assertGrants("after up", ownerA, viewerA, true)
			continue
		}
		if !granted(ownerA, "firewall.read") {
			t.Fatal("down removed a grant that existed before migration")
		}
		if granted(ownerA, "url_auth_policies.read") || granted(viewerA, "url_auth_policies.read") {
			t.Fatal("down kept a grant added by the migration")
		}
	}
	ownerB, viewerB := newTenant("role grants 459 b")
	assertGrants("new tenant after up", ownerB, viewerB, true)
}
