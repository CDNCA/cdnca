package openrestysecurity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type panicTx struct{ pgx.Tx }

func TestValidateActorRequiresPlatformSelfScope(t *testing.T) {
	scopeID := uuid.New()
	actor := Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: ScopePlatform,
		Permissions: []string{PermissionRead}}
	if err := validateActor(actor, scopeID, PermissionRead); err != nil {
		t.Fatalf("self-scope error = %v", err)
	}
	if err := validateActor(actor, uuid.New(), PermissionRead); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope error = %v, want ErrNotFound", err)
	}
	tenant := Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: ScopeTenant,
		Permissions: []string{PermissionRead}}
	if err := validateActor(tenant, scopeID, PermissionRead); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant self-scope error = %v, want ErrPermissionDenied", err)
	}
}

func TestIAMTxAuthorizerRejectsMissingActorPermissionBeforeLiveIAM(t *testing.T) {
	scopeID := uuid.New()
	actor := Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: ScopePlatform, Permissions: []string{"sites.read"}}.
		WithCredential(CredentialSession, uuid.New(), "session-token", nil)
	authorizer := iamTxAuthorizer{}
	for _, permission := range []string{PermissionRead, PermissionManage} {
		if err := authorizer.Authorize(context.Background(), &panicTx{}, actor, scopeID, permission); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("Authorize(%s) error = %v, want ErrPermissionDenied", permission, err)
		}
	}
}

// E1（live-click-A）：迁移 222 起 tenant_owner 不再有 openresty_security.*，
// 租户读系统规则目录/规则组改为 security_policies.read；平台与写操作不变。
func TestValidateRuleGroupActorTenantUsesSecurityPolicyRead(t *testing.T) {
	scopeID, tenantID := uuid.New(), uuid.New()
	tenant := func(permissions ...string) Actor {
		return Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: ScopeTenant, Permissions: permissions}.
			WithCredential(CredentialSession, uuid.New(), "session-token", &tenantID)
	}
	if err := validateRuleGroupActor(tenant("security_policies.read"), scopeID); err != nil {
		t.Fatalf("tenant security_policies.read error = %v, want nil", err)
	}
	for _, permissions := range [][]string{{PermissionRead}, {PermissionManage}, {"security_policies.manage"}, {"sites.read"}} {
		if err := validateRuleGroupActor(tenant(permissions...), scopeID); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant %v error = %v, want ErrPermissionDenied", permissions, err)
		}
	}
	platform := func(permissions ...string) Actor {
		return Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: ScopePlatform, Permissions: permissions}
	}
	if err := validateRuleGroupActor(platform(PermissionRead), scopeID); err != nil {
		t.Fatalf("platform openresty_security.read error = %v, want nil", err)
	}
	if err := validateRuleGroupActor(platform("security_policies.read"), scopeID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("platform security_policies.read error = %v, want ErrPermissionDenied", err)
	}
}

func TestIAMTxAuthorizerTenantStillCannotManageWithSecurityPolicyRead(t *testing.T) {
	scopeID, tenantID := uuid.New(), uuid.New()
	actor := Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: ScopeTenant,
		Permissions: []string{"security_policies.read", "security_policies.manage"}}.
		WithCredential(CredentialSession, uuid.New(), "session-token", &tenantID)
	for _, permission := range []string{PermissionRead, PermissionManage} {
		if err := (iamTxAuthorizer{}).Authorize(context.Background(), &panicTx{}, actor, scopeID, permission); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant Authorize(%s) error = %v, want ErrPermissionDenied", permission, err)
		}
	}
	// 非规则组路径不得借 security_policies.read 通过 authorize 的权限白名单。
	if err := (iamTxAuthorizer{}).authorize(context.Background(), &panicTx{}, actor, scopeID, TenantRuleGroupReadPermission, false); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("authorize(security_policies.read, allowTenant=false) error = %v, want ErrPermissionDenied", err)
	}
}
