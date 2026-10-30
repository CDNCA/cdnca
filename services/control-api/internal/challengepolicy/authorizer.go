package challengepolicy

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type denyTxAuthorizer struct{}

func (denyTxAuthorizer) Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) (uuid.UUID, error) {
	return uuid.Nil, ErrPermissionDenied
}

type TenantSessionAuthorizer interface {
	AuthorizeTenantSessionTx(
		context.Context,
		pgx.Tx,
		rbacmanager.AuthenticatedSessionReference,
		string,
	) (uuid.UUID, error)
}

type tenantSessionTxAuthorizer struct {
	sessions TenantSessionAuthorizer
}

func NewTenantSessionTxAuthorizer(sessions TenantSessionAuthorizer) (TxAuthorizer, error) {
	if isNilDependency(sessions) {
		return nil, ErrInvalidStoreConfig
	}
	return tenantSessionTxAuthorizer{sessions: sessions}, nil
}

func (authorizer tenantSessionTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if tx == nil || actor.ScopeKind != "tenant" || actor.ScopeID != targetScopeID ||
		actor.Credential.Kind != CredentialKindSession || actor.Credential.ID == uuid.Nil {
		return uuid.Nil, ErrPermissionDenied
	}
	tenantID, err := authorizer.sessions.AuthorizeTenantSessionTx(ctx, tx,
		rbacmanager.AuthenticatedSessionReference{
			UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.Credential.ID,
		}, permission)
	if errors.Is(err, rbacmanager.ErrPermissionDenied) {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, err
}
