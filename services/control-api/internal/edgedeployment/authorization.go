package edgedeployment

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) protectedOperationError() error {
	if s == nil || !configuredPool(s.pool) || s.now == nil || s.auditor == nil || nilInterface(s.auditor) {
		return ErrUnavailable
	}
	if s.authorizer == nil {
		return ErrPermissionDenied
	}
	if !s.authorizer.Configured() {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) authorizeSession(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (iamlock.Authorization, error) {
	return s.authorizeSessionPermissions(ctx, tx, actor, targetScopeID, []string{permission})
}

// authorizeSessionPermissions locks the session scopes once and requires every
// permission; one session must not be authorized twice in a transaction.
func (s *Store) authorizeSessionPermissions(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permissions []string,
) (iamlock.Authorization, error) {
	rawSession := actor.rawSession()
	if s == nil || s.authorizer == nil || tx == nil || rawSession == "" {
		return iamlock.Authorization{}, ErrPermissionDenied
	}
	authorization, err := s.authorizer.AuthorizeSessionPermissions(ctx, tx, rawSession, targetScopeID, permissions)
	if err != nil {
		return iamlock.Authorization{}, stableAuthorizationError(err)
	}
	tenantID, tenantTarget := authorization.TenantID()
	// A tenant target equal to the authentication scope proves tenant auth;
	// iamlock only permits a different authentication scope for platform auth.
	if !authorization.Valid() || authorization.UserID() != actor.UserID ||
		authorization.AuthenticationScopeID() != actor.ScopeID || authorization.TargetScopeID() != targetScopeID ||
		authorization.CredentialID() != actor.SessionID || authorization.CredentialKind() != "session" ||
		!tenantTarget || tenantID == uuid.Nil ||
		(actor.ScopeKind == ScopeKindPlatform && actor.ScopeID == targetScopeID) ||
		(actor.ScopeKind == ScopeKindTenant && actor.ScopeID != targetScopeID) {
		return iamlock.Authorization{}, ErrPermissionDenied
	}
	return authorization, nil
}

func stableAuthorizationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, iamlock.ErrInvalidCredential):
		return ErrUnauthenticated
	case errors.Is(err, iamlock.ErrPermissionDenied), errors.Is(err, iamlock.ErrInvalidInput):
		return ErrPermissionDenied
	default:
		return ErrUnavailable
	}
}

func stableOperationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	}
	for _, domainErr := range []error{
		ErrInvalidInput, ErrIdempotencyConflict, ErrUnauthenticated, ErrPermissionDenied, ErrNotFound,
		ErrInvalidTransition, ErrRevisionConflict, ErrRetriesExhausted, ErrDeadlineExpired, ErrUnavailable,
	} {
		if errors.Is(err, domainErr) {
			return domainErr
		}
	}
	return ErrUnavailable
}
