package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestPluginInstallations145Contract(t *testing.T) {
	up := readPluginInstallations145(t, "145_plugin_installations.up.sql")
	down := readPluginInstallations145(t, "145_plugin_installations.down.sql")
	for _, required := range []string{
		"migration 145 requires the exact verified 144 release head",
		"version = 144 AND migration_id = '144_waf_geo_authority'",
		"7fac4e1bdec793d461ef3a1735c81d4b7c020dd876fa565dd919a68bb493ce95",
		"51d17cc3aac3ad80f4d3afc968e2ed504b608558aed521a0a75f2ef99f31ea2c",
		"CREATE TABLE plugin_installation_heads",
		"CREATE TABLE plugin_installation_receipts",
		"UNIQUE (tenant_scope_id, authorization_id, idempotency_key)",
		"protect_plugin_installation_receipt_145",
		"validate_plugin_installation_head_145",
		"prevent_plugin_installation_truncate_145",
		"plugin_installations.read",
		"plugin_installations.manage",
		"valid_plugin_installation_scopes_145(scope_values text[])",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("145 up missing %q", required)
		}
	}
	if strings.Contains(up, "valid_plugin_installation_scopes_145(values text[])") {
		t.Fatal("145 up must not use the reserved VALUES keyword as a function parameter")
	}
	if guard, mutation := strings.Index(up, "migration 145 requires the exact verified 144 release head"),
		strings.Index(up, "INSERT INTO permissions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("145 predecessor guard must run before the first mutation")
	}
	for _, required := range []string{
		"migration 145 rollback requires the exact verified 145 head",
		"migration 145 rollback would discard plugin installation facts",
		"DROP TABLE plugin_installation_receipts",
		"DROP TABLE plugin_installation_heads",
		"DELETE FROM permissions WHERE name IN ('plugin_installations.read','plugin_installations.manage')",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("145 down missing %q", required)
		}
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("145 down must not mutate the migration ledger")
	}
}

func readPluginInstallations145(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
