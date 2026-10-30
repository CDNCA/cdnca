package errorpagecontrol

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

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

// NewTenantSessionTxAuthorizer preserves the legacy tenant-only adapter for
// compatibility tests. NewRuntimeHandler uses identity plus iamlock directly.
func NewTenantSessionTxAuthorizer(sessions TenantSessionAuthorizer) (TxAuthorizer, error) {
	if isNilDependency(sessions) {
		return nil, ErrInvalidStore
	}
	return tenantSessionTxAuthorizer{sessions: sessions}, nil
}

func (authorizer tenantSessionTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	permission string,
) error {
	if tx == nil || actor.ScopeKind != "tenant" ||
		actor.Credential.Kind != CredentialKindSession || actor.Credential.ID == uuid.Nil {
		return ErrPermissionDenied
	}
	_, err := authorizer.sessions.AuthorizeTenantSessionTx(ctx, tx,
		rbacmanager.AuthenticatedSessionReference{
			UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.Credential.ID,
		}, permission)
	if errors.Is(err, rbacmanager.ErrPermissionDenied) {
		return ErrPermissionDenied
	}
	return err
}
