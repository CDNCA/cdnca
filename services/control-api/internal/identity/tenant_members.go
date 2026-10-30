package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Tenant members. A
// tenant administrator (identity.users.manage, or the tenant owner's
// identity.roles.manage) lists the members of its own tenant scope; the
// console picks from it the member a custom role is granted to. Adding,
// suspending, resuming and deleting members, resetting their passwords and
// sending invitations were removed in 1.0.35; a member
// joins through an invitation already mailed or a platform-created account.

type TenantMember struct {
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       *string   `json:"email"`
	Status      string    `json:"status"`
	Role        string    `json:"role"`
	Owner       bool      `json:"owner"`
	CreatedAt   time.Time `json:"created_at"`
	// PasswordChangeRequired: must change the password at the next sign-in.
	PasswordChangeRequired bool `json:"password_change_required"`
}

const tenantMemberPermissionsSQL = `SELECT EXISTS(SELECT 1 FROM role_assignments assignment
	JOIN role_permissions permission ON permission.role_id=assignment.role_id
	WHERE assignment.scope_id=$1 AND assignment.user_id=$2
	  AND permission.permission_name IN ('identity.users.manage','identity.roles.manage'))`

func (s *Store) authorizeTenantMemberAdminTx(ctx context.Context, tx pgx.Tx, actor Principal) error {
	if actor.ScopeKind != "tenant" || actor.TenantID == nil {
		return ErrPermissionDenied
	}
	var allowed bool
	if err := tx.QueryRow(ctx, tenantMemberPermissionsSQL, actor.ScopeID, actor.UserID).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// tenantOwnerSQL: the scope's owner is its earliest membership.
const tenantOwnerSQL = `(SELECT owner.user_id FROM memberships owner WHERE owner.scope_id=$1 ORDER BY owner.created_at, owner.user_id LIMIT 1)`

func (s *Store) ListTenantMembers(ctx context.Context, actor Principal) ([]TenantMember, error) {
	var members []TenantMember
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT u.id,u.username,u.display_name,u.email,
			CASE WHEN u.status<>'active' THEN u.status ELSE m.status END,
			COALESCE((SELECT role.name FROM role_assignments assignment JOIN roles role ON role.id=assignment.role_id
				WHERE assignment.scope_id=m.scope_id AND assignment.user_id=m.user_id ORDER BY role.name LIMIT 1),''),
			u.id=`+tenantOwnerSQL+`, m.created_at, u.password_change_required
			FROM memberships m JOIN users u ON u.id=m.user_id
			WHERE m.scope_id=$1 AND NOT EXISTS(SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=u.id)
			ORDER BY m.created_at, u.id LIMIT 500`, actor.ScopeID)
		if err != nil {
			return err
		}
		members, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (TenantMember, error) {
			var member TenantMember
			return member, row.Scan(&member.UserID, &member.Username, &member.DisplayName, &member.Email,
				&member.Status, &member.Role, &member.Owner, &member.CreatedAt, &member.PasswordChangeRequired)
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list tenant members: %w", err)
	}
	return members, nil
}

// ListTenantMembers is the service entry point.
func (s *Service) ListTenantMembers(ctx context.Context, actor Principal) ([]TenantMember, error) {
	return s.store.ListTenantMembers(ctx, actor)
}
