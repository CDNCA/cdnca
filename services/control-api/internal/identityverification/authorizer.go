package identityverification

import (
	"context"
	"errors"
	"reflect"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type denyTxAuthorizer struct{}

func (denyTxAuthorizer) Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, ...string) error {
	return ErrPermissionDenied
}

type sessionAuthorizer interface {
	AuthorizeSessionPermissions(context.Context, pgx.Tx, string, uuid.UUID, []string) (iamlock.Authorization, error)
}

type iamSessionTxAuthorizer struct {
	sessions sessionAuthorizer
}

func newIAMSessionTxAuthorizer(sessions sessionAuthorizer) (TxAuthorizer, error) {
	if isNilSessionAuthorizer(sessions) {
		return nil, ErrInvalidService
	}
	return iamSessionTxAuthorizer{sessions: sessions}, nil
}

func isNilSessionAuthorizer(authorizer sessionAuthorizer) bool {
	if authorizer == nil {
		return true
	}
	value := reflect.ValueOf(authorizer)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func (authorizer iamSessionTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permissions ...string,
) error {
	if authorizer.sessions == nil || tx == nil || !validActor(actor) ||
		actor.TenantScopeID() != targetScopeID || len(permissions) == 0 {
		return ErrPermissionDenied
	}
	if actor.PlatformReviewer() {
		// 平台管理员可代审（读/审核），不能以申请人或其他身份操作。
		for _, permission := range permissions {
			if permission != permissionRead && permission != permissionReview {
				return ErrPermissionDenied
			}
		}
	}
	// One call for all permissions: iamlock rejects a repeated AuthorizeSession
	// for one platform session in the same transaction (lock order guard).
	sealed, err := authorizer.sessions.AuthorizeSessionPermissions(ctx, tx, actor.rawSession,
		targetScopeID, permissions)
	if errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrInvalidInput) {
		return ErrPermissionDenied
	}
	if err != nil {
		return ErrUnavailable
	}
	_, hasTenant := sealed.TenantID()
	if !sealed.Valid() || !hasTenant || sealed.UserID() != actor.session.userID ||
		sealed.AuthenticationScopeID() != actor.session.scopeID ||
		sealed.TargetScopeID() != targetScopeID ||
		sealed.CredentialKind() != CredentialKindSession ||
		sealed.CredentialID() != actor.session.sessionID {
		return ErrPermissionDenied
	}
	if actor.PlatformReviewer() {
		// Same rule as every other tenant action (tenantaccess): platform.admin
		// in the platform scope and an active target tenant.
		allowed, err := tenantaccess.ActorMayActOnTenant(ctx, tx, actor.UserID, targetScopeID)
		if err != nil {
			return ErrUnavailable
		}
		admin, err := tenantaccess.IsPlatformAdmin(ctx, tx, actor.UserID, actor.ScopeID)
		if err != nil {
			return ErrUnavailable
		}
		if !allowed || !admin {
			return ErrPermissionDenied
		}
	}
	return nil
}

// authorizePlatformAdmin: the platform session itself, sealed in tx, with
// platform.admin in its platform scope (same rule as the tenant review path:
// read/review or platform.admin through iamlock, then tenantaccess).
func (authorizer iamSessionTxAuthorizer) authorizePlatformAdmin(ctx context.Context, tx pgx.Tx, admin PlatformAdmin) error {
	if authorizer.sessions == nil || tx == nil || !admin.Valid() {
		return ErrPermissionDenied
	}
	sealed, err := authorizer.sessions.AuthorizeSessionPermissions(ctx, tx, admin.rawSession, admin.ScopeID,
		[]string{permissionRead, permissionReview})
	if errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrInvalidInput) {
		return ErrPermissionDenied
	}
	if err != nil {
		return ErrUnavailable
	}
	if _, hasTenant := sealed.TenantID(); !sealed.Valid() || hasTenant || sealed.UserID() != admin.UserID ||
		sealed.AuthenticationScopeID() != admin.ScopeID || sealed.TargetScopeID() != admin.ScopeID ||
		sealed.CredentialKind() != CredentialKindSession || sealed.CredentialID() != admin.sessionID {
		return ErrPermissionDenied
	}
	ok, err := tenantaccess.IsPlatformAdmin(ctx, tx, admin.UserID, admin.ScopeID)
	if err != nil {
		return ErrUnavailable
	}
	if !ok {
		return ErrPermissionDenied
	}
	return nil
}

type platformAdminAuthorizer interface {
	authorizePlatformAdmin(context.Context, pgx.Tx, PlatformAdmin) error
}

// AuthorizePlatformAdminList revalidates the platform administrator session in
// the cross-tenant list transaction.
func (s *Service) AuthorizePlatformAdminList(ctx context.Context, tx pgx.Tx, admin PlatformAdmin) error {
	if s == nil || tx == nil || !admin.Valid() {
		return ErrPermissionDenied
	}
	authorizer, ok := s.authorizer.(platformAdminAuthorizer)
	if !ok {
		return ErrPermissionDenied
	}
	err := authorizer.authorizePlatformAdmin(ctx, tx, admin)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrPermissionDenied):
		return ErrPermissionDenied
	default:
		return ErrUnavailable
	}
}

func (s *Service) authorizeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permissions ...string,
) error {
	if s == nil || isNilTxAuthorizer(s.authorizer) {
		return ErrPermissionDenied
	}
	err := s.authorizer.Authorize(ctx, tx, actor, targetScopeID, permissions...)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrPermissionDenied):
		return ErrPermissionDenied
	default:
		return ErrUnavailable
	}
}

// AuthorizeReviewerList revalidates the sealed reviewer session in the list transaction.
func (s *Service) AuthorizeReviewerList(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if tx == nil || !validActor(actor) {
		return ErrPermissionDenied
	}
	return s.authorizeWrite(ctx, tx, actor, actor.TenantScopeID(), permissionRead, permissionReview)
}

// AuthorizeCreateDraft checks live IAM state before the HTTP adapter reserves
// external evidence. The create transaction authorizes again before any write.
func (s *Service) AuthorizeCreateDraft(ctx context.Context, actor Actor) error {
	if s == nil || s.pool == nil {
		return ErrInvalidService
	}
	if !validActor(actor) {
		return ErrInvalidInput
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.authorizeWrite(ctx, tx, actor, actor.ScopeID, permissionSelfManage)
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

func isNilTxAuthorizer(authorizer TxAuthorizer) bool {
	if authorizer == nil {
		return true
	}
	value := reflect.ValueOf(authorizer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
