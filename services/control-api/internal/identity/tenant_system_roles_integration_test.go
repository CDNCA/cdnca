//go:build integration

package identity_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// E2（live-click-A）：新建租户的 owner 权限集合必须等于存量 tenant_owner
// 在迁移头上的集合。存量角色在迁移 1 上创建（无权限），
// 迁到头后得到全部迁移回填，再补上同一份显式清单；新角色在头上经
// SeedTenantSystemRoles 创建（显式清单 + roles 触发器）。任何“只回填存量、
// 新建路径漏掉”或“只有触发器、存量未回填”的权限都会让两者不等。
func TestTenantOwnerSeedMatchesMigrationHead(t *testing.T) {
	pool := databasetest.MigratedThroughPool(t, "tenant_role_seed", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	legacy := insertTenantSystemRoleScope(t, ctx, pool)
	// 只放存量 owner：存量 tenant_viewer 过不了迁移 148（其 sites.export 回填被 094 守卫拒绝，
	// 186 只修了触发器），属既有迁移缺陷，另行回报。
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'legacy',true)`, legacy.owner, legacy.scope, identity.UserRoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate legacy tenant to head: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		SELECT $1,name FROM permissions WHERE name=ANY($2::text[]) ON CONFLICT DO NOTHING`,
		legacy.owner, identity.TenantOwnerPermissions); err != nil {
		t.Fatal(err)
	}

	fresh := insertTenantSystemRoleScope(t, ctx, pool)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return identity.SeedTenantSystemRoles(ctx, tx, fresh.scope, fresh.owner, fresh.viewer, time.Now().UTC())
	}); err != nil {
		t.Fatalf("seed fresh tenant roles: %v", err)
	}

	head, created := rolePermissionSet(t, ctx, pool, legacy.owner), rolePermissionSet(t, ctx, pool, fresh.owner)
	missing, extra := setDifference(head, created), setDifference(created, head)
	t.Logf("tenant_owner: migration head %d, new tenant %d", len(head), len(created))
	if len(missing) > 0 || len(extra) > 0 {
		t.Errorf("tenant_owner drift: new tenant missing %v; new tenant extra %v", missing, extra)
	}
}

type tenantSystemRoleScope struct{ scope, owner, viewer uuid.UUID }

func insertTenantSystemRoleScope(t *testing.T, ctx context.Context, pool *pgxpool.Pool) tenantSystemRoleScope {
	t.Helper()
	tenantID := uuid.New()
	result := tenantSystemRoleScope{scope: uuid.New(), owner: uuid.New(), viewer: uuid.New()}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'Role seed tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`,
		result.scope, tenantID); err != nil {
		t.Fatal(err)
	}
	return result
}

func rolePermissionSet(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT permission_name FROM role_permissions WHERE role_id=$1 ORDER BY 1`, roleID)
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return permissions
}

func setDifference(left, right []string) []string {
	result := []string{}
	for _, item := range left {
		if !slices.Contains(right, item) {
			result = append(result, item)
		}
	}
	return result
}
