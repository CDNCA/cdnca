package tenantaccess

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Nil identities never reach the database and are never allowed.
func TestNilIdentitiesAreRefusedWithoutQuery(t *testing.T) {
	ctx := context.Background()
	if ok, err := IsPlatformAdmin(ctx, nil, uuid.Nil, uuid.New()); ok || err != nil {
		t.Fatalf("nil user: ok=%t err=%v", ok, err)
	}
	if ok, err := ActorMayActOnTenant(ctx, nil, uuid.New(), uuid.Nil); ok || err != nil {
		t.Fatalf("nil tenant: ok=%t err=%v", ok, err)
	}
}

// The SQL predicate is the tenant member branch OR the 435 platform admin
// function, on an active tenant scope.
func TestActorOnTenantSQLShape(t *testing.T) {
	sql := ActorOnTenantSQL("u.id", "s.id")
	for _, want := range []string{
		"ta_membership.user_id=u.id", "ta_scope.id=s.id AND ta_scope.kind='tenant'",
		"ta_tenant.status='active'", "ta_membership.status='active'", "ta_account.status='active'",
		"OR EXISTS (SELECT 1 FROM access_scopes ta_target", "control_platform_admin_435(u.id,NULL)",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("predicate lacks %q:\n%s", want, sql)
		}
	}
	if got := PlatformAdminSQL("$1", "$2"); got != "control_platform_admin_435($1,$2)" {
		t.Fatalf("PlatformAdminSQL=%q", got)
	}
}
