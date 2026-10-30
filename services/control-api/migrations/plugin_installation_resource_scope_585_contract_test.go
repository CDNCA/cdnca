package migrations

import (
	"strings"
	"testing"
)

// Migration 585 (fix-plugconfirm, placeholder number): plugin installation heads record the signed
// resource scope; platform plugin installation permissions go to platform_owner only.
func TestPluginInstallationResourceScope585Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"585_plugin_installation_resource_scope.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 584", "(SELECT max(version) FROM schema_migrations) <> 584",
			"migration_id='584_recharge_payment_compensations'",
			"checksum_sha256='55913a3b89e36e5041ebda5cfdb037c8f5b2962c32c4dd354bfc6d1f2e0403a6'",
			"down_checksum_sha256='c04940f5184e01162ae638f94fb3411cceb70f8b01884314f5050c1ced75e491'",
			"ERRCODE='P5850'", "CHECK (resource_scope IN ('platform','tenant'))",
			"ERRCODE='P5851'", "ERRCODE='P5852'", "scope.kind=NEW.resource_scope",
			"'plugin_installations.platform.read'", "'plugin_installations.platform.manage'",
			"scope.kind = 'platform'", "role.name = 'platform_owner'",
		}},
		{"585_plugin_installation_resource_scope.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 585", "migration_id='585_plugin_installation_resource_scope'",
			"ERRCODE='P5853'", "resource_scope='platform'", "ERRCODE='P5854'",
			"DROP COLUMN resource_scope",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
	up, _ := FS.ReadFile("585_plugin_installation_resource_scope.up.sql")
	if guard, mutation := strings.Index(string(up), "ERRCODE='P5850'"),
		strings.Index(string(up), "ALTER TABLE plugin_installation_heads"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("585 predecessor guard must run before the first mutation")
	}
}
