package firewallhttp

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// API-JOBS-02：Actor.Permissions 必须是本次凭据的真实有效权限，不能写死 read+manage。
func TestRuntimeActorCarriesEffectivePermissions(t *testing.T) {
	tenantID := uuid.New()
	principal := identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: firewallcontrol.ScopeTenant, TenantID: &tenantID,
		Permissions: []string{firewallcontrol.PermissionRead},
	}
	actor := runtimeActor(principal, firewallcontrol.CredentialAPIKey, uuid.Nil, "cdnca_key_example.secret")
	if slices.Contains(actor.Permissions, firewallcontrol.PermissionManage) ||
		!slices.Equal(actor.Permissions, []string{firewallcontrol.PermissionRead}) {
		t.Fatalf("actor permissions=%v, want only read", actor.Permissions)
	}
	principal.Permissions[0] = "mutated"
	if actor.Permissions[0] != firewallcontrol.PermissionRead {
		t.Fatal("actor permissions alias the principal slice")
	}
	if empty := runtimeActor(identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: firewallcontrol.ScopeTenant, TenantID: &tenantID},
		firewallcontrol.CredentialSession, uuid.New(), "token"); len(empty.Permissions) != 0 {
		t.Fatalf("principal without permissions produced %v", empty.Permissions)
	}
}
