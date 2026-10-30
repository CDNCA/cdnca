package jobhttp

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// commandAPIKeyGrant 是事务内复核 API 密钥后得到的事实，用于与认证时的 Principal 比对。
type commandAPIKeyGrant struct {
	keyID, userID, authenticationScopeID, targetScopeID uuid.UUID
}

// commandAPIKeyAuthorizer 在命令事务内复核 API 密钥（生产实现包装 iamlock.AuthorizeAPIKey）。
type commandAPIKeyAuthorizer interface {
	authorizeAPIKey(ctx context.Context, tx pgx.Tx, raw string, targetScopeID uuid.UUID, permission string) (commandAPIKeyGrant, error)
}

type iamCommandAPIKeyAuthorizer struct{ iam *iamlock.Authorizer }

func (authorizer iamCommandAPIKeyAuthorizer) authorizeAPIKey(
	ctx context.Context, tx pgx.Tx, raw string, targetScopeID uuid.UUID, permission string,
) (commandAPIKeyGrant, error) {
	sealed, err := authorizer.iam.AuthorizeAPIKey(ctx, tx, raw, targetScopeID, permission)
	if err != nil {
		return commandAPIKeyGrant{}, err
	}
	if !sealed.Valid() || sealed.CredentialKind() != "api_key" {
		return commandAPIKeyGrant{}, iamlock.ErrPermissionDenied
	}
	return commandAPIKeyGrant{
		keyID: sealed.CredentialID(), userID: sealed.UserID(),
		authenticationScopeID: sealed.AuthenticationScopeID(), targetScopeID: sealed.TargetScopeID(),
	}, nil
}

// authorizeCommandAPIKey 在命令事务内复核本次 API 密钥（API-JOBS-02）：认证之后、事务之前
// 密钥被吊销、过期、缩权或所属用户/成员关系停用时拒绝。iamlock 要求 IAM 全局锁是事务内
// 第一个有效锁，因此必须在 authorizeLiveCommand 等任何行锁之前调用。Bearer 会话不复核。
func authorizeCommandAPIKey(ctx context.Context, tx pgx.Tx, authorizer commandAPIKeyAuthorizer, input CommandInput) error {
	credential := input.Principal.apiKey
	if credential == nil {
		return nil
	}
	if input.Audience != AudienceTenant || input.Principal.ScopeKind != ScopeTenant {
		// API 密钥只属于租户（apikey/service.go），不能走平台命令。
		return ErrScopeForbidden
	}
	if authorizer == nil {
		return ErrStoreUnavailable
	}
	if credential.keyID == uuid.Nil || credential.raw == "" {
		return ErrPermissionDenied
	}
	grant, err := authorizer.authorizeAPIKey(ctx, tx, credential.raw, input.Principal.ScopeID, PermissionManage)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// ErrInvalidCredential 包装了 ErrPermissionDenied；锁协议错误（ErrLockOrder 等）按不可用处理。
		if errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrInvalidInput) {
			return ErrPermissionDenied
		}
		return ErrStoreUnavailable
	}
	if grant.keyID != credential.keyID || grant.userID != input.Principal.UserID ||
		grant.authenticationScopeID != input.Principal.ScopeID || grant.targetScopeID != input.Principal.ScopeID {
		return ErrPermissionDenied
	}
	return nil
}
