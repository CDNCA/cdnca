package migrations

import (
	"strings"
	"testing"
)

// Migration 688: the plugin probe
// request idempotency index is per installation and tenant, on the exact
// verified 687 head; down restores the 639 index and refuses while two
// tenants of one installation share a key.
func TestProbeDNSPupPluginTenantIdempotency688Contract(t *testing.T) {
	up, err := FS.ReadFile("688_probe_dnspup_plugin_tenant_idempotency.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("688_probe_dnspup_plugin_tenant_idempotency.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 687", "(SELECT max(version) FROM schema_migrations) <> 687",
		"migration_id='687_active_config_identity_rollback_failed_serving'", "ERRCODE='P6880'",
		"CREATE UNIQUE INDEX probe_dnspup_plugin_requests_idem_688_uq\n    ON probe_dnspup_plugin_requests(installation_id, tenant_scope_id, idempotency_key)\n    WHERE origin = 'plugin';",
		"DROP INDEX probe_dnspup_plugin_requests_idem_639_uq;",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("688 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 688",
		"migration_id='688_probe_dnspup_plugin_tenant_idempotency'", "ERRCODE='P6881'", "ERRCODE='P6882'",
		"GROUP BY installation_id, idempotency_key HAVING count(*) > 1",
		"CREATE UNIQUE INDEX probe_dnspup_plugin_requests_idem_639_uq ON probe_dnspup_plugin_requests(installation_id, idempotency_key)\n    WHERE origin = 'plugin';",
		"DROP INDEX probe_dnspup_plugin_requests_idem_688_uq;",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("688 down missing %q", fragment)
		}
	}
	for name, sql := range map[string][]byte{"up": up, "down": down} {
		if strings.Contains(string(sql), "INSERT INTO") || strings.Contains(string(sql), "UPDATE ") ||
			strings.Contains(string(sql), "DELETE FROM") || strings.Contains(string(sql), "ALTER TABLE") {
			t.Errorf("688 %s must only swap the index", name)
		}
	}
}
