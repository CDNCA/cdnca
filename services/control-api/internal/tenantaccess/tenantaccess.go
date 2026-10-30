// Package tenantaccess is the one rule for acting on a tenant's resources
// ("管理员是第一权限，没有不能操作的"): an active member of the
// tenant scope, or a platform administrator — an active platform member
// holding platform.admin in that platform scope. Ordinary non-members are
// still refused. The SQL side is control_platform_admin_435 (migration 435).
package tenantaccess

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PlatformAdminPermission is the platform-wide super permission.
const PlatformAdminPermission = "platform.admin"

// Querier is the part of pgx.Tx / pgxpool.Pool the checks need.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PlatformAdminSQL is the SQL predicate for "userExpr is a platform
// administrator in platform scope scopeExpr"; scopeExpr "NULL" accepts any
// platform scope. Both arguments are SQL expressions (placeholders or columns).
func PlatformAdminSQL(userExpr, scopeExpr string) string {
	return "control_platform_admin_435(" + userExpr + "," + scopeExpr + ")"
}

// IsPlatformAdmin reports whether userID is an active platform member holding
// platform.admin in platformScopeID.
func IsPlatformAdmin(ctx context.Context, q Querier, userID, platformScopeID uuid.UUID) (bool, error) {
	if userID == uuid.Nil || platformScopeID == uuid.Nil {
		return false, nil
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT `+PlatformAdminSQL("$1", "$2"), userID, platformScopeID).Scan(&ok); err != nil {
		return false, fmt.Errorf("check platform administrator: %w", err)
	}
	return ok, nil
}

// ActorMayActOnTenant: userID is an active member of the active tenant scope
// tenantScopeID, or a platform administrator (in any platform scope).
func ActorMayActOnTenant(ctx context.Context, q Querier, userID, tenantScopeID uuid.UUID) (bool, error) {
	if userID == uuid.Nil || tenantScopeID == uuid.Nil {
		return false, nil
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT `+ActorOnTenantSQL("$1", "$2"), userID, tenantScopeID).Scan(&ok); err != nil {
		return false, fmt.Errorf("check tenant actor: %w", err)
	}
	return ok, nil
}

// ActorOnTenantSQL is the SQL predicate behind ActorMayActOnTenant.
func ActorOnTenantSQL(userExpr, tenantScopeExpr string) string {
	return `(EXISTS (SELECT 1 FROM access_scopes ta_scope
		JOIN tenants ta_tenant ON ta_tenant.id=ta_scope.tenant_id AND ta_tenant.status='active'
		JOIN memberships ta_membership ON ta_membership.scope_id=ta_scope.id
		 AND ta_membership.user_id=` + userExpr + ` AND ta_membership.status='active'
		JOIN users ta_account ON ta_account.id=ta_membership.user_id AND ta_account.status='active'
		WHERE ta_scope.id=` + tenantScopeExpr + ` AND ta_scope.kind='tenant')
	OR EXISTS (SELECT 1 FROM access_scopes ta_target
		JOIN tenants ta_target_tenant ON ta_target_tenant.id=ta_target.tenant_id AND ta_target_tenant.status='active'
		WHERE ta_target.id=` + tenantScopeExpr + ` AND ta_target.kind='tenant'
		  AND ` + PlatformAdminSQL(userExpr, "NULL") + `))`
}
