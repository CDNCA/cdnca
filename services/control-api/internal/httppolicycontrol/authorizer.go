package httppolicycontrol

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type denyTxAuthorizer struct{}

func (denyTxAuthorizer) AuthorizeWrite(context.Context, pgx.Tx, Actor, uuid.UUID, string) (uuid.UUID, error) {
	return uuid.Nil, ErrPermissionDenied
}

type tenantSessionAuthorizer interface {
	AuthorizeTenantSessionTx(
		context.Context,
		pgx.Tx,
		rbacmanager.AuthenticatedSessionReference,
		string,
	) (uuid.UUID, error)
}

type tenantSessionTxAuthorizer struct {
	sessions tenantSessionAuthorizer
}

func NewTenantSessionTxAuthorizer(sessions *rbacmanager.Service) (TxAuthorizer, error) {
	if sessions == nil {
		return nil, ErrInvalidStoreConfig
	}
	return denyTxAuthorizer{}, nil
}

func NewTenantSessionStore(
	pool *pgxpool.Pool,
	now func() time.Time,
	trust *entitlementguard.TrustStore,
	sessions *rbacmanager.Service,
) (*Store, error) {
	if _, err := NewTenantSessionTxAuthorizer(sessions); err != nil {
		return nil, err
	}
	return newStoreWithAuthorizer(pool, now, trust, denyTxAuthorizer{})
}

func (authorizer tenantSessionTxAuthorizer) AuthorizeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if tx == nil || authorizer.sessions == nil || !validTenantSessionActor(actor, targetScopeID) {
		return uuid.Nil, ErrPermissionDenied
	}
	tenantID, err := authorizer.sessions.AuthorizeTenantSessionTx(ctx, tx,
		rbacmanager.AuthenticatedSessionReference{
			UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.Credential.ID,
		}, permission)
	if errors.Is(err, rbacmanager.ErrPermissionDenied) {
		return uuid.Nil, ErrPermissionDenied
	}
	if err != nil {
		return uuid.Nil, err
	}
	var targetTenantID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes
		WHERE id=$1 AND kind='tenant' AND tenant_id=$2 FOR SHARE`,
		targetScopeID, tenantID).Scan(&targetTenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrPermissionDenied
	}
	if err != nil {
		return uuid.Nil, err
	}
	if tenantID == uuid.Nil || targetTenantID != tenantID {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

func validTenantSessionActor(actor Actor, targetScopeID uuid.UUID) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeID == targetScopeID &&
		actor.ScopeKind == "tenant" && actor.Credential.Kind == CredentialKindSession &&
		actor.Credential.ID != uuid.Nil
}
