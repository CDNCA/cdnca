//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestTenantOrderRecordsReadOnly498: up/down/up; existing and newly created
// tenant_owner roles hold billing.order_records.read but not .manage; down
// gives manage back and drops the read code.
func TestTenantOrderRecordsReadOnly498(t *testing.T) {
	const version = 498
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, ownerRole := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'498 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_owner','498 owner',true)`, ownerRole, scopeID)
	holds := func(roleID uuid.UUID, permission string) bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_permissions
			WHERE role_id=$1 AND permission_name=$2)`, roleID, permission).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	if !holds(ownerRole, "billing.order_records.manage") {
		t.Fatal("497 tenant_owner should hold billing.order_records.manage")
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		wantRead := step == "up"
		if holds(ownerRole, "billing.order_records.read") != wantRead ||
			holds(ownerRole, "billing.order_records.manage") == wantRead {
			t.Fatalf("after %s: read=%t manage=%t", step, holds(ownerRole, "billing.order_records.read"),
				holds(ownerRole, "billing.order_records.manage"))
		}
	}
	otherTenant, otherScope, newOwner := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'498 new tenant')`, otherTenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, otherScope, otherTenant)
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_owner','498 new owner',true)`, newOwner, otherScope)
	if !holds(newOwner, "billing.order_records.read") || holds(newOwner, "billing.order_records.manage") {
		t.Fatal("new tenant_owner after 498 must get only billing.order_records.read")
	}
}
