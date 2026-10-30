package migrations

import (
	"strings"
	"testing"
)

func TestAccountOrderRecords207Contract(t *testing.T) {
	up, err := FS.ReadFile("207_account_order_records.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("207_account_order_records.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration_id='206_dns_legacy_settings'",
		"billing.order_records.manage",
		"custom_rbac_permission_catalog",
		"grant_account_order_record_permission_207",
		"CREATE TABLE account_order_records",
		"CREATE TABLE account_order_record_events",
		"CREATE TABLE account_order_record_write_receipts",
		"account order record heads cannot be deleted",
		"account_order_record_events_append_only_207",
		"UNIQUE(actor_session_id,operation,idempotency_key)",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"migration_id='207_account_order_records'",
		"rollback would discard account order record facts",
		"DELETE FROM role_permissions",
		"DELETE FROM custom_rbac_permission_catalog",
		"DELETE FROM permissions",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}
}
