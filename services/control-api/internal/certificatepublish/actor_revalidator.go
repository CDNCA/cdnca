package certificatepublish

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ActorRevalidator struct{}

func NewActorRevalidator() *ActorRevalidator { return &ActorRevalidator{} }

func (*ActorRevalidator) AuthorizeCertificatePublication(
	ctx context.Context,
	tx pgx.Tx,
	actor edgedeployment.Actor,
	targetScopeID uuid.UUID,
	reference edgedeployment.CertificateActorReference,
) (uuid.UUID, uuid.UUID, error) {
	if ctx == nil || tx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil ||
		actor.SessionID == uuid.Nil || targetScopeID == uuid.Nil ||
		reference.UserRevision < 1 || reference.TargetTenantID == uuid.Nil || reference.TargetTenantRevision < 1 {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
	}
	if err := iamlock.AcquireShared(ctx, tx); err != nil {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID, targetScopeID}); err != nil {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	var sessionUserID, sessionScopeID uuid.UUID
	var revokedAt, expiresAt *time.Time
	var replacedByID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT user_id,scope_id,revoked_at,replaced_by_id,expires_at
		FROM auth_sessions WHERE id=$1 FOR SHARE`, actor.SessionID).Scan(
		&sessionUserID, &sessionScopeID, &revokedAt, &replacedByID, &expiresAt,
	); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
	} else if err != nil {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&databaseNow); err != nil {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	if sessionUserID != actor.UserID || sessionScopeID != actor.ScopeID || revokedAt != nil ||
		replacedByID != nil || expiresAt == nil || !expiresAt.After(databaseNow) {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
	}

	var accountRevision int64
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT revision,status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).Scan(
		&accountRevision, &accountStatus,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
		}
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	var membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR SHARE`,
		actor.ScopeID, actor.UserID).Scan(&membershipStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
		}
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	var actorScopeKind, targetScopeKind string
	var targetTenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT actor_scope.kind,target_scope.kind,target_scope.tenant_id
		FROM access_scopes actor_scope CROSS JOIN access_scopes target_scope
		WHERE actor_scope.id=$1 AND target_scope.id=$2`, actor.ScopeID, targetScopeID).Scan(
		&actorScopeKind, &targetScopeKind, &targetTenantID,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
		}
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	var tenantRevision int64
	var tenantStatus string
	if targetTenantID == nil {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
	}
	if err := tx.QueryRow(ctx, `SELECT revision,status FROM tenants WHERE id=$1 FOR SHARE`, *targetTenantID).Scan(
		&tenantRevision, &tenantStatus,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
		}
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	if accountStatus != "active" || accountRevision != reference.UserRevision || membershipStatus != "active" ||
		actorScopeKind != actor.ScopeKind || targetScopeKind != "tenant" ||
		*targetTenantID != reference.TargetTenantID || tenantRevision != reference.TargetTenantRevision ||
		tenantStatus != "active" || (actor.ScopeKind == "tenant" && actor.ScopeID != targetScopeID) ||
		(actor.ScopeKind != "tenant" && actor.ScopeKind != "platform") {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM role_assignments assignment
			JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
			JOIN role_permissions grant_row ON grant_row.role_id=role.id
			JOIN permissions permission ON permission.name=grant_row.permission_name
			WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND permission.name='certificates.manage'
		)`, actor.ScopeID, actor.UserID).Scan(&allowed); err != nil {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnavailable
	}
	if !allowed {
		return uuid.Nil, uuid.Nil, edgedeployment.ErrUnauthenticated
	}
	return actor.UserID, actor.ScopeID, nil
}

var _ edgedeployment.CertificatePublisherAuthorizer = (*ActorRevalidator)(nil)
