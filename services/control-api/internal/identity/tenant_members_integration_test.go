//go:build integration

package identity_test

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// TestTenantMembersList: the tenant administrator lists the members of its
// own scope (owner first); a viewer and another tenant cannot.
func TestTenantMembersList(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	owner, scopeID := seedTenantMemberOwner(t, fixture)
	memberID, otherScope, otherTenant := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Alice','x')`, []any{memberID, "alice-" + uuid.NewString()[:8]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, memberID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) SELECT $1,$2,id FROM roles WHERE scope_id=$1 AND name='tenant_viewer'`, []any{scopeID, memberID}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Other Tenant')`, []any{otherTenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{otherScope, otherTenant}},
	} {
		if _, err := fixture.pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	members, err := fixture.service.ListTenantMembers(ctx, owner)
	if err != nil || len(members) != 2 || !members[0].Owner || members[1].UserID != memberID || members[1].Owner ||
		members[1].Role != identity.UserRoleViewer {
		t.Fatalf("list: %+v %v", members, err)
	}
	viewer := identity.Principal{UserID: memberID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: owner.TenantID}
	if _, err := fixture.service.ListTenantMembers(ctx, viewer); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("viewer list: %v", err)
	}
	stranger := identity.Principal{UserID: owner.UserID, ScopeID: otherScope, ScopeKind: "tenant", TenantID: &otherTenant}
	if _, err := fixture.service.ListTenantMembers(ctx, stranger); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("cross-tenant list: %v", err)
	}
}

// seedTenantMemberOwner creates a tenant scope with an owner that can manage
// members (tenant_owner with identity.roles.manage) and a tenant_viewer role.
func seedTenantMemberOwner(t *testing.T, fixture throttleFixture) (identity.Principal, uuid.UUID) {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	ownerID, ownerRole, viewerRole := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Member Tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Owner','x')`, []any{ownerID, "owner-" + uuid.NewString()[:8]}},
		{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,now()-interval '1 day')`, []any{scopeID, ownerID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$3,'tenant_owner','o',true),($2,$3,'tenant_viewer','v',true)`, []any{ownerRole, viewerRole, scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'identity.self.read'),($2,'identity.self.read')`, []any{ownerRole, viewerRole}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, ownerID, ownerRole}},
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return identity.Principal{UserID: ownerID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID}, scopeID
}
