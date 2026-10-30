package migrations

import (
	"strings"
	"testing"
)

// Migration 586 (fix-plugconfirm3, placeholder number): plugin installation heads record the signed plugin
// type, and one license authorization has exactly one local target binding on this controller.
func TestPluginInstallationTargetBinding586Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"586_plugin_installation_target_binding.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 585", "(SELECT max(version) FROM schema_migrations) <> 585",
			"migration_id='585_plugin_installation_resource_scope'",
			"checksum_sha256='2dfa02ec0d753032d123fa0bb5c7691b6717d24c86e3e8eab1e3dfbbf3bc3f33'",
			"down_checksum_sha256='6bd2fa2c71405a25331e49853120762d67aa38581b92c72841c3e7cd225858af'",
			"ERRCODE='P5860'", "ERRCODE='P5861'", "ERRCODE='P5862'",
			"(resource_scope='platform' AND entrypoint_type IN ('theme','rule_pack'))",
			"(resource_scope='tenant' AND entrypoint_type IN ('external_https','ui_page'))",
			"ON plugin_installation_heads(authorization_id)", "ALTER COLUMN entrypoint_type SET NOT NULL",
		}},
		{"586_plugin_installation_target_binding.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 586", "migration_id='586_plugin_installation_target_binding'",
			"ERRCODE='P5863'", "DROP INDEX plugin_installation_heads_authorization_586_uk", "DROP COLUMN entrypoint_type",
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
	up, _ := FS.ReadFile("586_plugin_installation_target_binding.up.sql")
	if guard, mutation := strings.Index(string(up), "ERRCODE='P5860'"),
		strings.Index(string(up), "ALTER TABLE plugin_installation_heads"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("586 predecessor guard must run before the first mutation")
	}
}
