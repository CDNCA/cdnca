//go:build integration

package identity_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestTenantMembersCreateSuspendResume(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	tenantID, scopeID := uuid.New(), uuid.New()
	ownerID, ownerRole, viewerRole := uuid.New(), uuid.New(), uuid.New()
	otherScope, otherTenant := uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Member Tenant'),($2,'Other Tenant')`, []any{tenantID, otherTenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`, []any{scopeID, tenantID, otherScope, otherTenant}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'member-owner','Owner','x')`, []any{ownerID}},
		{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,now()-interval '1 day')`, []any{scopeID, ownerID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$3,'tenant_owner','o',true),($2,$3,'tenant_viewer','v',true)`, []any{ownerRole, viewerRole, scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'identity.self.read'),($2,'identity.self.read')`, []any{ownerRole, viewerRole}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, ownerID, ownerRole}},
	} {
		if _, err := fixture.pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	owner := identity.Principal{UserID: ownerID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID}
	service := fixture.service

	if _, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{Username: "x", DisplayName: "", Password: "short", RequestID: "r"}); !errors.Is(err, identity.ErrInvalidUserInput) {
		t.Fatalf("invalid input: %v", err)
	}
	member, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
		Username: "Ops-Alice", DisplayName: "Alice", Email: "alice@example.com", Password: "LongEnough-Pass1", RequestID: "create-1"})
	if err != nil || member.Username != "ops-alice" || member.Role != identity.UserRoleViewer {
		t.Fatalf("create: %+v %v", member, err)
	}
	if _, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
		Username: "ops-alice", DisplayName: "Dup", Password: "LongEnough-Pass1", RequestID: "create-2"}); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("duplicate username: %v", err)
	}
	// The new sub-account signs in to this tenant scope.
	login, err := service.Login(ctx, identity.LoginInput{Username: "ops-alice", Password: "LongEnough-Pass1"},
		identity.RequestInfo{RequestID: "alice-login", SourceIP: "192.0.2.50"})
	if err != nil || login.Principal.ScopeID != scopeID {
		t.Fatalf("sub-account login: %+v %v", login.Principal, err)
	}
	members, err := service.ListTenantMembers(ctx, owner)
	if err != nil || len(members) != 2 || !members[0].Owner || members[1].UserID != member.UserID || members[1].Owner {
		t.Fatalf("list: %+v %v", members, err)
	}
	// A viewer cannot manage members; another tenant cannot see them.
	viewer := identity.Principal{UserID: member.UserID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID}
	if _, err := service.ListTenantMembers(ctx, viewer); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("viewer list: %v", err)
	}
	if _, err := service.SetTenantMemberStatus(ctx, owner, ownerID, false, nil, "self"); !errors.Is(err, identity.ErrTenantMemberProtected) {
		t.Fatalf("self suspend: %v", err)
	}
	stranger := identity.Principal{UserID: ownerID, ScopeID: otherScope, ScopeKind: "tenant", TenantID: &otherTenant}
	if _, err := service.SetTenantMemberStatus(ctx, stranger, member.UserID, false, nil, "x"); err == nil {
		t.Fatal("cross-tenant suspend allowed")
	}
	suspended, err := service.SetTenantMemberStatus(ctx, owner, member.UserID, false, nil, "suspend-1")
	if err != nil || suspended.Status != identity.MembershipStatusSuspended {
		t.Fatalf("suspend: %+v %v", suspended, err)
	}
	if _, err := service.Authenticate(ctx, login.AccessToken); !errors.Is(err, identity.ErrInvalidSession) {
		t.Fatalf("suspended member session still valid: %v", err)
	}
	resumed, err := service.SetTenantMemberStatus(ctx, owner, member.UserID, true, nil, "resume-1")
	if err != nil || resumed.Status != identity.MembershipStatusActive {
		t.Fatalf("resume: %+v %v", resumed, err)
	}
	var actions []string
	rows, err := fixture.pool.Query(ctx, `SELECT action FROM audit_events WHERE action LIKE 'identity.tenant_member.%' ORDER BY occurred_at`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var action string
		_ = rows.Scan(&action)
		actions = append(actions, action)
	}
	if strings.Join(actions, ",") != "identity.tenant_member.create,identity.tenant_member.suspend,identity.tenant_member.resume" {
		t.Fatalf("audit actions=%v", actions)
	}
}

func TestTenantMembersResetPasswordAndDelete(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	owner, scopeID := seedTenantMemberOwner(t, fixture)
	service := fixture.service
	setPasswordResetCipher(t, service)
	const password = "LongEnough-Pass1"
	member, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
		Username: "ops-bob", DisplayName: "Bob", Password: password, RequestID: "create-bob"})
	if err != nil {
		t.Fatal(err)
	}
	login := func(secret string) (identity.AuthResult, error) {
		return service.Login(ctx, identity.LoginInput{Username: "ops-bob", Password: secret},
			identity.RequestInfo{RequestID: "bob-" + uuid.NewString()[:8], SourceIP: "192.0.2.60"})
	}
	session, err := login(password)
	if err != nil {
		t.Fatal(err)
	}
	// Reset: the owner and the actor are protected; a viewer cannot reset.
	if _, err := service.ResetTenantMemberPassword(ctx, owner, owner.UserID, "k0", "r0"); !errors.Is(err, identity.ErrTenantMemberProtected) {
		t.Fatalf("self reset: %v", err)
	}
	viewer := identity.Principal{UserID: member.UserID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: owner.TenantID}
	if _, err := service.ResetTenantMemberPassword(ctx, viewer, owner.UserID, "k1", "r1"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("viewer reset: %v", err)
	}
	reset, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "reset-bob-key", "reset-bob")
	if err != nil || len(reset.TemporaryPassword) != 24 || !reset.PasswordChangeRequired || reset.Replayed {
		t.Fatalf("reset: %+v %v", reset, err)
	}
	temporary := reset.TemporaryPassword
	if _, err := service.Authenticate(ctx, session.AccessToken); !errors.Is(err, identity.ErrInvalidSession) {
		t.Fatalf("session after reset: %v", err)
	}
	if _, err := login(password); err == nil {
		t.Fatal("old password still works")
	}
	session, err = login(temporary)
	if err != nil {
		t.Fatalf("temporary password login: %v", err)
	}

	// Delete: refused while the member owns a live site.
	siteID := insertSecondaryVerificationSite(t, fixture.pool, scopeID, member.UserID, "bob.example.test", true, "", uuid.Nil)
	if err := service.DeleteTenantMember(ctx, owner, member.UserID, nil, "d1"); !errors.Is(err, identity.ErrTenantMemberOwnsResources) {
		t.Fatalf("delete with site: %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE sites SET deleted_at=now(),updated_at=now() WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteTenantMember(ctx, owner, owner.UserID, nil, "d2"); !errors.Is(err, identity.ErrTenantMemberProtected) {
		t.Fatalf("self delete: %v", err)
	}
	if err := service.DeleteTenantMember(ctx, owner, member.UserID, nil, "delete-bob"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := service.Authenticate(ctx, session.AccessToken); !errors.Is(err, identity.ErrInvalidSession) {
		t.Fatalf("session after delete: %v", err)
	}
	if _, err := login(temporary); err == nil {
		t.Fatal("deleted member can still sign in")
	}
	if err := service.DeleteTenantMember(ctx, owner, member.UserID, nil, "delete-again"); !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	members, err := service.ListTenantMembers(ctx, owner)
	if err != nil || len(members) != 1 {
		t.Fatalf("list after delete: %+v %v", members, err)
	}
	var deletedBy uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT deleted_by_user_id FROM identity_user_deletions WHERE user_id=$1`, member.UserID).Scan(&deletedBy); err != nil || deletedBy != owner.UserID {
		t.Fatalf("deletion fact: %v %v", deletedBy, err)
	}
	var actions []string
	rows, err := fixture.pool.Query(ctx, `SELECT action FROM audit_events WHERE action IN
		('identity.tenant_member.password.reset','identity.tenant_member.delete') ORDER BY occurred_at`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var action string
		_ = rows.Scan(&action)
		actions = append(actions, action)
	}
	if strings.Join(actions, ",") != "identity.tenant_member.password.reset,identity.tenant_member.delete" {
		t.Fatalf("audit actions=%v", actions)
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
