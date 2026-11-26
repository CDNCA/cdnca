package migrations

import (
	"strings"
	"testing"
)

// Migration 701: on the verified 700 head, a publication records
// whether it is a node settings redelivery of an earlier publication (its base) and the content
// refusal it was made for; inserting one checks the base is an earlier publication of the scope
// (P7011) and that the new version carries the base's site objects, snapshot and root apart
// from their identity (P7012). Down drops the trigger, its function and the columns.
func TestEdgePublicationNodeSettings701Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := read("701_edge_publication_node_settings.up.sql")
	down := read("701_edge_publication_node_settings.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, edge_config_publications IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 700", "(SELECT max(version) FROM schema_migrations) <> 700",
		"WHERE version=700 AND", "migration_id='700_control_upgrade_create_preparations'", "ERRCODE='P7010'",
		"ADD COLUMN publication_kind text NOT NULL DEFAULT 'content'",
		"CHECK (publication_kind IN ('content','node_settings'))",
		"ADD COLUMN node_settings_base_config_version_id uuid,",
		"ADD COLUMN content_refusal text,",
		"'rule_pack_out_of_profile','sdk_shield_port_shared'",
		"base.source_revision<NEW.source_revision", "ERRCODE='P7011'",
		"base_objects.member_sha256=next_objects.member_sha256",
		"- 'config_version_id' - 'source_revision' - 'document_sha256'", "ERRCODE='P7012'",
		"BEFORE INSERT ON edge_config_publications",
		"REVOKE ALL ON FUNCTION assert_edge_publication_node_settings_701() FROM PUBLIC;",
		"CREATE OR REPLACE FUNCTION site_publication_outcome_618(", "CREATE OR REPLACE FUNCTION site_sync_status_batch_663(",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("701 up missing %q", fragment)
		}
	}
	if got := strings.Count(up, "AND covering.publication_kind='content') THEN 'request_failed'"); got != 2 {
		t.Errorf("701 up: %d site sync request_failed branches read the publication kind, want 2", got)
	}
	if strings.Contains(down, "covering.publication_kind") {
		t.Error("701 down still reads the publication kind")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 701",
		"migration_id='701_edge_publication_node_settings'", "ERRCODE='P7010'",
		"DROP TRIGGER edge_config_publications_node_settings_701 ON edge_config_publications;",
		"DROP FUNCTION assert_edge_publication_node_settings_701();",
		"DROP COLUMN publication_kind;",
		"CREATE OR REPLACE FUNCTION site_publication_outcome_618(", "CREATE OR REPLACE FUNCTION site_sync_status_batch_663(",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("701 down missing %q", fragment)
		}
	}
}
