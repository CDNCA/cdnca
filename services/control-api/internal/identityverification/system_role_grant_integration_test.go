//go:build integration

package identityverification

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// E5: tenant system roles created after migration 037 (every tenant created by
// the user store or registration) must receive the identity verification
// permissions 037 granted to the roles that existed at migration time.
func TestTenantSystemRolesCreatedAfterMigrationReceiveIdentityVerificationPermissions(t *testing.T) {
	// 迁移 459 补上 roles AFTER INSERT 授权触发器 + 存量回填。
	// 459 之前实测：tenant_owner 缺 self.manage/read/review，tenant_viewer 缺 self.manage。
	pool := databasetest.MigratedPool(t, nil)
	ctx := context.Background()
	tenantID, scopeID, ownerID, viewerID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'iv grant tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','Tenant owner',true)`,
			[]any{ownerID, scopeID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_viewer','Tenant viewer',true)`,
			[]any{viewerID, scopeID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for roleID, want := range map[uuid.UUID][]string{
		ownerID:  {permissionSelfManage, "identity_verification.read", "identity_verification.review"},
		viewerID: {permissionSelfManage},
	} {
		for _, permission := range want {
			var granted bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_permissions
				WHERE role_id=$1 AND permission_name=$2)`, roleID, permission).Scan(&granted); err != nil {
				t.Fatal(err)
			}
			if !granted {
				t.Errorf("role %s missing %s", roleID, permission)
			}
		}
	}
}
