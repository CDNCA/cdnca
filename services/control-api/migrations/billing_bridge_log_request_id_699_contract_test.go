package migrations

import (
	"strings"
	"testing"
)

// Migration 699: on the exact verified 698 head,
// billing_bridge_logs gets a nullable request_id (the X-Request-ID the response and error body carry) with
// partial indexes for the owner's request_id and external_service_id filters; reason_code stays required for
// denied, may now be set on a failure and stays NULL on a success. Down clears failure reasons, restores the
// 556 check and drops the column and indexes.
func TestBillingBridgeLogRequestID699Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("699_billing_bridge_log_request_id.up.sql"), read("699_billing_bridge_log_request_id.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 698", "(SELECT max(version) FROM schema_migrations) <> 698",
		"migration_id='698_package_subscription_suspend_source'",
		"table_name='billing_bridge_logs' AND column_name='request_id'", "ERRCODE='P6990'",
		"ADD COLUMN request_id text",
		"CHECK (request_id IS NULL OR request_id ~ '^[A-Za-z0-9._-]{1,128}$')",
		"DROP CONSTRAINT billing_bridge_logs_reason_556_check",
		"(result <> 'denied' OR reason_code IS NOT NULL) AND (result <> 'success' OR reason_code IS NULL)",
		"ON billing_bridge_logs (owner_scope_id, request_id, created_at DESC, id DESC)\n    WHERE request_id IS NOT NULL;",
		"ON billing_bridge_logs (owner_scope_id, external_service_id, created_at DESC, id DESC)\n    WHERE external_service_id IS NOT NULL;",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("699 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 699", "migration_id='699_billing_bridge_log_request_id'",
		"ERRCODE='P6991'",
		"DROP INDEX billing_bridge_logs_service_699_idx;", "DROP INDEX billing_bridge_logs_request_699_idx;",
		"UPDATE billing_bridge_logs SET reason_code = NULL WHERE result = 'failure' AND reason_code IS NOT NULL;",
		"ADD CONSTRAINT billing_bridge_logs_reason_556_check CHECK ((result = 'denied') = (reason_code IS NOT NULL))",
		"DROP COLUMN request_id;",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("699 down missing %q", fragment)
		}
	}
	// Down restores the check before the column goes, after the failure reasons are cleared.
	if strings.Index(down, "UPDATE billing_bridge_logs") > strings.Index(down, "ADD CONSTRAINT billing_bridge_logs_reason_556_check") {
		t.Error("699 down restores the 556 check before clearing failure reasons")
	}
}
