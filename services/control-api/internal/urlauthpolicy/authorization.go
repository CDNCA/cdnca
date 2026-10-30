package urlauthpolicy

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type iamTxAuthorizer struct {
	iam *iamlock.Authorizer
}

func NewIAMTxAuthorizer(authorizer *iamlock.Authorizer) (TxAuthorizer, error) {
	if authorizer == nil || !authorizer.Configured() {
		return nil, ErrUnavailable
	}
	return iamTxAuthorizer{iam: authorizer}, nil
}

func (authorizer iamTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if tx == nil || targetScopeID == uuid.Nil || actor.rawCredential == "" ||
		(permission != PermissionRead && permission != PermissionManage) {
		return uuid.Nil, ErrPermissionDenied
	}
	var sealed iamlock.Authorization
	var err error
	switch actor.credentialKind {
	case CredentialSession:
		sealed, err = authorizer.iam.AuthorizeSession(ctx, tx, actor.rawCredential, targetScopeID, permission)
	case CredentialAPIKey:
		sealed, err = authorizer.iam.AuthorizeAPIKey(ctx, tx, actor.rawCredential, targetScopeID, permission)
	default:
		return uuid.Nil, ErrPermissionDenied
	}
	if err != nil {
		if ctx.Err() != nil {
			return uuid.Nil, ctx.Err()
		}
		switch {
		case errors.Is(err, iamlock.ErrInvalidCredential):
			return uuid.Nil, ErrUnauthenticated
		case errors.Is(err, iamlock.ErrPermissionDenied), errors.Is(err, iamlock.ErrInvalidInput):
			return uuid.Nil, ErrPermissionDenied
		default:
			return uuid.Nil, ErrUnavailable
		}
	}
	if !sealed.Valid() || sealed.UserID() != actor.UserID ||
		sealed.AuthenticationScopeID() != actor.ScopeID || sealed.TargetScopeID() != targetScopeID ||
		sealed.CredentialKind() != actor.credentialKind {
		return uuid.Nil, ErrPermissionDenied
	}
	if actor.credentialKind == CredentialSession &&
		(actor.credentialID == uuid.Nil || sealed.CredentialID() != actor.credentialID) {
		return uuid.Nil, ErrPermissionDenied
	}
	tenantID, ok := sealed.TenantID()
	if !ok || tenantID == uuid.Nil {
		return uuid.Nil, ErrPermissionDenied
	}
	if actor.ScopeKind == "tenant" {
		if actor.ScopeID != targetScopeID || actor.tenantID == nil || *actor.tenantID != tenantID {
			return uuid.Nil, ErrPermissionDenied
		}
	} else if actor.ScopeKind != "platform" || actor.tenantID != nil || actor.credentialKind != CredentialSession {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

type snapshotTxAuthorizer struct{}

func (snapshotTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if tx == nil || !validActor(actor) || targetScopeID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage) ||
		actor.ScopeKind == "tenant" && actor.ScopeID != targetScopeID {
		return uuid.Nil, ErrPermissionDenied
	}
	var tenantID *uuid.UUID
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1`, targetScopeID).Scan(&kind, &tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrPermissionDenied
		}
		return uuid.Nil, err
	}
	if kind != "tenant" || tenantID == nil || *tenantID == uuid.Nil {
		return uuid.Nil, ErrPermissionDenied
	}
	return *tenantID, nil
}
