//go:build integration

package identity_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestAdminAccessAllowlistGatesPlatformSessionsOnly(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	// A tenant user in its own scope.
	tenantID, tenantScope, tenantUser := uuid.New(), uuid.New(), uuid.New()
	hash, _ := identity.HashPassword("Tenant-password-1")
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Access Tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{tenantScope, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'access-tenant','Tenant',$2)`, []any{tenantUser, hash}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{tenantScope, tenantUser}},
	} {
		if _, err := fixture.pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := fixture.service.Login(ctx, identity.LoginInput{Username: fixture.username, Password: fixture.password},
		identity.RequestInfo{RequestID: "admin-login", SourceIP: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	// Saving a list that excludes the saving address is refused.
	if _, err := fixture.service.UpdateAdminAccessPolicy(ctx, admin.Principal, identity.UpdateAdminAccessPolicyInput{
		ExpectedRevision: 0, Enabled: true, Allowlist: []string{"198.51.100.0/24"}, SourceIP: "203.0.113.5", RequestID: "save-1",
	}); !errors.Is(err, identity.ErrAdminAccessSelfLockout) {
		t.Fatalf("self lockout: %v", err)
	}
	if _, err := fixture.service.UpdateAdminAccessPolicy(ctx, admin.Principal, identity.UpdateAdminAccessPolicyInput{
		ExpectedRevision: 0, Enabled: true, Allowlist: []string{}, SourceIP: "203.0.113.5", RequestID: "save-2",
	}); !errors.Is(err, identity.ErrAdminAccessInvalidInput) {
		t.Fatalf("empty enabled list: %v", err)
	}
	policy, err := fixture.service.UpdateAdminAccessPolicy(ctx, admin.Principal, identity.UpdateAdminAccessPolicyInput{
		ExpectedRevision: 0, Enabled: true, Allowlist: []string{"203.0.113.9/24"}, SourceIP: "203.0.113.5", RequestID: "save-3",
	})
	if err != nil || policy.Revision != 1 || len(policy.Allowlist) != 1 || policy.Allowlist[0] != "203.0.113.0/24" {
		t.Fatalf("save: %+v %v", policy, err)
	}
	if _, err := fixture.service.UpdateAdminAccessPolicy(ctx, admin.Principal, identity.UpdateAdminAccessPolicyInput{
		ExpectedRevision: 0, Enabled: false, Allowlist: []string{}, SourceIP: "203.0.113.5", RequestID: "save-4",
	}); !errors.Is(err, identity.ErrAdminAccessRevision) {
		t.Fatalf("stale revision: %v", err)
	}
	from := func(address string) context.Context {
		return audit.WithSourceIP(ctx, netip.MustParseAddr(address))
	}
	if _, err := fixture.service.Authenticate(from("203.0.113.77"), admin.AccessToken); err != nil {
		t.Fatalf("allowed source: %v", err)
	}
	if _, err := fixture.service.Authenticate(from("127.0.0.1"), admin.AccessToken); err != nil {
		t.Fatalf("loopback: %v", err)
	}
	if _, err := fixture.service.Authenticate(from("198.51.100.4"), admin.AccessToken); !errors.Is(err, identity.ErrAdminAccessDenied) {
		t.Fatalf("outside source: %v", err)
	}
	if _, err := fixture.service.AuthenticateSession(ctx, admin.AccessToken); !errors.Is(err, identity.ErrAdminAccessDenied) {
		t.Fatalf("unknown source: %v", err)
	}
	if _, err := fixture.service.Login(ctx, identity.LoginInput{Username: fixture.username, Password: fixture.password},
		identity.RequestInfo{RequestID: "admin-login-2", SourceIP: "198.51.100.4"}); !errors.Is(err, identity.ErrAdminAccessDenied) {
		t.Fatalf("admin login outside: %v", err)
	}
	// Tenants are not affected.
	tenant, err := fixture.service.Login(ctx, identity.LoginInput{Username: "access-tenant", Password: "Tenant-password-1"},
		identity.RequestInfo{RequestID: "tenant-login", SourceIP: "198.51.100.4"})
	if err != nil {
		t.Fatalf("tenant login: %v", err)
	}
	if _, err := fixture.service.Authenticate(from("198.51.100.4"), tenant.AccessToken); err != nil {
		t.Fatalf("tenant session: %v", err)
	}
	// Recovery: the root-local CLI path turns it off.
	disabled, err := identity.NewStore(fixture.pool).DisableAdminAccessPolicy(ctx, uuid.NewString())
	if err != nil || disabled.Enabled || disabled.Revision != 2 {
		t.Fatalf("disable: %+v %v", disabled, err)
	}
	time.Sleep(5100 * time.Millisecond) // policy cache TTL
	if _, err := fixture.service.Authenticate(from("198.51.100.4"), admin.AccessToken); err != nil {
		t.Fatalf("after disable: %v", err)
	}
	var actions []string
	rows, err := fixture.pool.Query(ctx, `SELECT action FROM audit_events WHERE action LIKE 'system.admin_access.%' ORDER BY occurred_at`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var action string
		_ = rows.Scan(&action)
		actions = append(actions, action)
	}
	if strings.Join(actions, ",") != "system.admin_access.update,system.admin_access.disable" {
		t.Fatalf("audit actions = %v", actions)
	}
}
