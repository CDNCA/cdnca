package migrations

import (
	"strings"
	"testing"
)

// Migration 604 (plugapi-S2, after S1's 603 dns_records_manage_permission): an API key may be bound to an enabled plugin installation of its
// tenant at creation time; the binding is immutable. The predecessor is
// pinned by checksum.
func TestAPIKeyPluginInstallation604Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"604_api_key_plugin_installation.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 603", "(SELECT max(version) FROM schema_migrations) <> 603",
			"migration_id='603_dns_records_manage_permission'",
			"checksum_sha256='3e520ea363b24824a25b2239569ea6b9c06f09eab8f58ef69f6c31e280a31ccd'",
			"down_checksum_sha256='606bf2c9d0e06fdeb283c0a26a35d451929bbcfa768d11689d9428ec39a10550'",
			"ERRCODE='P6040'", "ADD COLUMN plugin_installation_authorization_id uuid",
			"REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id) ON DELETE RESTRICT",
			"binding is immutable' USING ERRCODE='P6041'", "head_status IS DISTINCT FROM 'enabled'",
			"ERRCODE='P6042'", "BEFORE INSERT OR UPDATE ON api_keys",
		}},
		{"604_api_key_plugin_installation.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 604", "migration_id='604_api_key_plugin_installation'",
			"ERRCODE='P6043'", "plugin_installation_authorization_id IS NOT NULL", "ERRCODE='P6044'",
			"DROP COLUMN plugin_installation_authorization_id",
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
}
