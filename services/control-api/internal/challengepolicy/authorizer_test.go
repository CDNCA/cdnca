package challengepolicy

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type testAuthorizationHooks struct {
	backendPID       chan<- int
	entered          chan<- struct{}
	beforeAccount    chan<- struct{}
	beforePermission chan<- struct{}
	authorized       chan<- struct{}
	release          <-chan struct{}
}

type testTxAuthorizer struct {
	hooks      *testAuthorizationHooks
	permission string
}

func (authorizer testTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if authorizer.hooks != nil && authorizer.hooks.backendPID != nil {
		var backendPID int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
			return uuid.Nil, err
		}
		authorizer.hooks.backendPID <- backendPID
	}
	if authorizer.hooks != nil && authorizer.hooks.entered != nil {
		authorizer.hooks.entered <- struct{}{}
	}
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || targetScopeID == uuid.Nil ||
		actor.Credential.Kind != CredentialKindSession || actor.Credential.ID == uuid.Nil ||
		(actor.ScopeKind != "tenant" && actor.ScopeKind != "platform") {
		return uuid.Nil, ErrPermissionDenied
	}
	var actorKind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&actorKind); err != nil {
		return uuid.Nil, authorizationTestError(err)
	}
	if actorKind != actor.ScopeKind || (actorKind == "tenant" && actor.ScopeID != targetScopeID) {
		return uuid.Nil, ErrPermissionDenied
	}
	var tenantID uuid.UUID
	var tenantStatus string
	if err := tx.QueryRow(ctx, `
		SELECT target.tenant_id, tenant.status
		FROM access_scopes target
		JOIN tenants tenant ON tenant.id=target.tenant_id
		WHERE target.id=$1 AND target.kind='tenant'
		FOR SHARE OF target,tenant`, targetScopeID).Scan(&tenantID, &tenantStatus); err != nil {
		return uuid.Nil, authorizationTestError(err)
	}
	if tenantStatus != "active" {
		return uuid.Nil, ErrPermissionDenied
	}
	if authorizer.hooks != nil && authorizer.hooks.beforeAccount != nil {
		authorizer.hooks.beforeAccount <- struct{}{}
	}
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).Scan(&accountStatus); err != nil {
		return uuid.Nil, authorizationTestError(err)
	}
	if accountStatus != "active" {
		return uuid.Nil, ErrPermissionDenied
	}
	var membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, actor.ScopeID, actor.UserID).Scan(&membershipStatus); err != nil {
		return uuid.Nil, authorizationTestError(err)
	}
	if membershipStatus != "active" {
		return uuid.Nil, ErrPermissionDenied
	}
	var sessionActive bool
	if err := tx.QueryRow(ctx, `SELECT revoked_at IS NULL AND expires_at>CURRENT_TIMESTAMP
		FROM auth_sessions WHERE id=$1 AND user_id=$2 AND scope_id=$3 FOR SHARE`,
		actor.Credential.ID, actor.UserID, actor.ScopeID).Scan(&sessionActive); err != nil {
		return uuid.Nil, authorizationTestError(err)
	}
	if !sessionActive {
		return uuid.Nil, ErrPermissionDenied
	}
	if authorizer.hooks != nil && authorizer.hooks.beforePermission != nil {
		authorizer.hooks.beforePermission <- struct{}{}
	}
	var granted string
	requiredPermission := permission
	if authorizer.permission != "" {
		requiredPermission = authorizer.permission
	}
	err := tx.QueryRow(ctx, `SELECT permission.permission_name
		FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		  AND permission.permission_name IN ($3,'platform.admin')
		ORDER BY role.id,permission.permission_name LIMIT 1
		FOR SHARE OF assignment,role,permission`, actor.ScopeID, actor.UserID, requiredPermission).Scan(&granted)
	if err != nil {
		return uuid.Nil, authorizationTestError(err)
	}
	if authorizer.hooks != nil && authorizer.hooks.authorized != nil {
		authorizer.hooks.authorized <- struct{}{}
	}
	if authorizer.hooks != nil && authorizer.hooks.release != nil {
		select {
		case <-ctx.Done():
			return uuid.Nil, ctx.Err()
		case <-authorizer.hooks.release:
		}
	}
	return tenantID, nil
}

func authorizationTestError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	return err
}
