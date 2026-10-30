package edgepublish

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error
}

type denyWriteAuthorizer struct{}

func (denyWriteAuthorizer) Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error {
	return ErrPermissionDenied
}

type iamWriteAuthorizer struct {
	authorizer *iamlock.Authorizer
}

func (authorizer iamWriteAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) error {
	rawSession := actor.rawSession()
	if authorizer.authorizer == nil || tx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil ||
		(actor.ScopeKind != ScopeKindPlatform && actor.ScopeKind != ScopeKindTenant) || actor.SessionID == uuid.Nil || rawSession == "" ||
		targetScopeID == uuid.Nil {
		return ErrPermissionDenied
	}
	sealed, err := authorizer.authorizer.AuthorizeSession(ctx, tx, rawSession, targetScopeID, permission)
	if err != nil {
		return mapIAMAuthorizationError(ctx, err)
	}
	_, hasTenant := sealed.TenantID()
	if !sealed.Valid() || !hasTenant || sealed.UserID() != actor.UserID ||
		sealed.AuthenticationScopeID() != actor.ScopeID || sealed.TargetScopeID() != targetScopeID ||
		sealed.CredentialKind() != "session" || sealed.CredentialID() != actor.SessionID {
		return ErrPermissionDenied
	}
	if actor.ScopeKind == ScopeKindTenant && actor.ScopeID != targetScopeID {
		return ErrPermissionDenied
	}
	return nil
}

func mapIAMAuthorizationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, iamlock.ErrInvalidCredential) {
		return ErrUnauthenticated
	}
	if errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrInvalidInput) {
		return ErrPermissionDenied
	}
	return fmt.Errorf("%w: authorize publication", ErrPersistence)
}
