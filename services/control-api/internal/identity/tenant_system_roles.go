package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Permissions a new tenant's system roles receive explicitly. Admin-created
// users (CreateManagedUser) and self registration (accountregistration) both
// seed through SeedTenantSystemRoles, so this is the single source. Grants
// that migration triggers add on INSERT INTO roles (042, 053-057, 079, 094,
// 148, 230, 429, 457 and others) must not be listed here: the explicit insert
// would collide with the trigger's row.
// TestTenantOwnerSeedMatchesMigrationHead keeps this equal to what migrations
// give an existing tenant_owner / tenant_viewer.
var (
	TenantOwnerPermissions = []string{
		"identity.self.read", "identity.self.update", "identity.password.change",
		"sites.read", "sites.manage", "dns.read", "dns.manage", "certificates.read", "certificates.manage",
		"streams.read", "streams.manage", "billing.account.read", "billing.recharges.create", "api_keys.self.manage",
	}
	TenantViewerPermissions = []string{
		"identity.self.read", "identity.self.update", "identity.password.change",
		"sites.read", "dns.read", "certificates.read",
		"streams.read", "billing.account.read", "api_keys.self.manage",
	}
)

// SeedTenantSystemRoles creates the tenant_owner and tenant_viewer system
// roles of a new tenant scope with their permissions.
func SeedTenantSystemRoles(ctx context.Context, tx pgx.Tx, scopeID, ownerRoleID, viewerRoleID uuid.UUID, createdAt time.Time) error {
	for _, role := range []struct {
		id          uuid.UUID
		name        string
		description string
		permissions []string
	}{
		{ownerRoleID, UserRoleOwner, "Tenant owner", TenantOwnerPermissions},
		{viewerRoleID, UserRoleViewer, "Tenant viewer", TenantViewerPermissions},
	} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO roles (id, scope_id, name, description, system_role, created_at)
			VALUES ($1, $2, $3, $4, true, $5)`, role.id, scopeID, role.name, role.description, createdAt); err != nil {
			return fmt.Errorf("insert %s role: %w", role.name, err)
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_name)
			SELECT $1, name FROM permissions WHERE name = ANY($2::text[])`, role.id, role.permissions)
		if err != nil {
			return fmt.Errorf("insert %s role permissions: %w", role.name, err)
		}
		if tag.RowsAffected() != int64(len(role.permissions)) {
			return fmt.Errorf("insert %s role permissions: expected %d, inserted %d", role.name, len(role.permissions), tag.RowsAffected())
		}
	}
	return nil
}
