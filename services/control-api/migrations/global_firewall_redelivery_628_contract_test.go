package migrations

import (
	"strings"
	"testing"
)

// Migration 628 (on top of 627
// node_deployment_host_replacements): global firewall commands carry delivery (0 = the
// publication's projection, >0 = a per-node redelivery), unique per
// (publication_id,node_id,site_id,delivery), immutable; down refuses while
// redeliveries exist.
func TestGlobalFirewallRedelivery628Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"628_global_firewall_redelivery.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 627", "(SELECT max(version) FROM schema_migrations) <> 627",
			"migration_id='627_node_deployment_host_replacements'", "ERRCODE='P6280'", "ERRCODE='P6281'",
			"ADD COLUMN delivery integer NOT NULL DEFAULT 0",
			"CHECK(delivery>=0 AND (delivery=0 OR policy_kind='global'))",
			"DROP CONSTRAINT firewall_command_outbox_publication_node_site_key",
			"UNIQUE(publication_id,node_id,site_id,delivery)",
			"BEFORE UPDATE ON firewall_command_outbox",
		}, []string{"DELETE FROM", "UPDATE firewall_command_outbox", "DROP TABLE", "BEFORE DELETE"}},
		{"628_global_firewall_redelivery.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 628", "migration_id='628_global_firewall_redelivery'",
			"ERRCODE='P6282'", "ERRCODE='P6283'", "WHERE delivery>0",
			"DROP COLUMN delivery", "ADD CONSTRAINT firewall_command_outbox_publication_node_site_key UNIQUE(publication_id,node_id,site_id)",
		}, []string{"DELETE FROM", "UPDATE firewall_command_outbox", "DROP TABLE"}},
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
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
}
