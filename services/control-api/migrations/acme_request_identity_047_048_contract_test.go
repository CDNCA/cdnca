package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestACMERequestIdentity047048Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		content, err := controlmigrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(content)), " ")
	}
	up047, down047 := read("047_acme_worker.up.sql"), read("047_acme_worker.down.sql")
	up048 := read("048_dns_acme_runtime.up.sql")

	for _, required := range []string{
		"request_snapshot ? 'TenantID'", "request_snapshot ? 'ScopeID'",
		"request_snapshot ? 'ActorUserID'", "request_snapshot ->> 'ScopeID' = tenant_scope_id::text",
		"validate_acme_issuance_operation_snapshot_047", "scope.kind = 'tenant'",
		"snapshot_tenant_id IS DISTINCT FROM scope_tenant_id", "membership.status = 'active'",
		"account.status = 'active'", "tenant.status = 'active'",
	} {
		if !strings.Contains(up047, required) {
			t.Errorf("047 up missing %q", required)
		}
	}
	if strings.Contains(up047, "request_snapshot ->> 'TenantID' = tenant_scope_id::text") {
		t.Fatal("047 still aliases tenant identity to scope identity")
	}
	for _, required := range []string{
		"DROP TRIGGER IF EXISTS acme_issuance_operation_snapshot_validate_047",
		"DROP FUNCTION IF EXISTS validate_acme_issuance_operation_snapshot_047()",
	} {
		if !strings.Contains(down047, required) {
			t.Errorf("047 down missing %q", required)
		}
	}
	for _, required := range []string{
		"NEW.request_snapshot ->> 'ScopeID' = scope.id::text",
		"NEW.request_snapshot ->> 'TenantID' = tenant.id::text",
		"order_row.created_by_user_id IS DISTINCT FROM NEW.actor_user_id",
		"order_row.dns_provider_id IS DISTINCT FROM NEW.dns_provider_id",
		"acme_runtime_actor_is_active_048(NEW.tenant_scope_id, NEW.actor_user_id)",
	} {
		if !strings.Contains(up048, required) {
			t.Errorf("048 up missing %q", required)
		}
	}
}
