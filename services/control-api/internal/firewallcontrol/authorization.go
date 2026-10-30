package firewallcontrol

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type iamTxAuthorizer struct{ iam *iamlock.Authorizer }

func NewIAMTxAuthorizer(iam *iamlock.Authorizer) (TxAuthorizer, error) {
	if iam == nil || !iam.Configured() {
		return nil, ErrUnavailable
	}
	return iamTxAuthorizer{iam: iam}, nil
}

func (authorizer iamTxAuthorizer) Authorize(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID, permission string) error {
	if tx == nil || actor.rawCredential == "" || targetScopeID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage) {
		return ErrPermissionDenied
	}
	var sealed iamlock.Authorization
	var err error
	switch actor.credentialKind {
	case CredentialSession:
		sealed, err = authorizer.iam.AuthorizeSession(ctx, tx, actor.rawCredential, targetScopeID, permission)
	case CredentialAPIKey:
		sealed, err = authorizer.iam.AuthorizeAPIKey(ctx, tx, actor.rawCredential, targetScopeID, permission)
	default:
		return ErrPermissionDenied
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case errors.Is(err, iamlock.ErrInvalidCredential):
			return ErrUnauthenticated
		case errors.Is(err, iamlock.ErrPermissionDenied), errors.Is(err, iamlock.ErrInvalidInput):
			return ErrPermissionDenied
		default:
			return ErrUnavailable
		}
	}
	if !sealed.Valid() || sealed.UserID() != actor.UserID || sealed.AuthenticationScopeID() != actor.ScopeID ||
		sealed.TargetScopeID() != targetScopeID || sealed.CredentialKind() != actor.credentialKind {
		return ErrUnauthenticated
	}
	if actor.credentialKind == CredentialSession && (actor.credentialID == uuid.Nil || sealed.CredentialID() != actor.credentialID) {
		return ErrUnauthenticated
	}
	tenantID, ok := sealed.TenantID()
	if !ok || tenantID == uuid.Nil {
		return ErrPermissionDenied
	}
	if actor.ScopeKind == ScopeTenant {
		if actor.ScopeID != targetScopeID || actor.tenantID == nil || *actor.tenantID != tenantID {
			return ErrUnauthenticated
		}
	} else if actor.ScopeKind != ScopePlatform || actor.tenantID != nil || actor.credentialKind != CredentialSession {
		return ErrPermissionDenied
	}
	return nil
}
