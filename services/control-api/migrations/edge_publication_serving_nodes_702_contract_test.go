package migrations

import (
	"strings"
	"testing"
)

// Migration 702 (G8): on the verified 701 head, every
// site object release records its serving nodes in an immutable table (P7021)
// that the stop overlay and the node settings redelivery read for their
// withheld websites and forwards. Down drops the table and its function.
func TestEdgePublicationServingNodes702Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := read("702_edge_publication_serving_nodes.up.sql")
	down := read("702_edge_publication_serving_nodes.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 701", "(SELECT max(version) FROM schema_migrations) <> 701",
		"WHERE version=701 AND", "migration_id='701_edge_publication_node_settings'", "ERRCODE='P7020'",
		"CREATE TABLE edge_publication_serving_nodes (",
		"config_version_id uuid PRIMARY KEY REFERENCES config_versions(id) ON DELETE RESTRICT",
		"jsonb_typeof(serving->'node_sets')='array'", "ERRCODE='P7021'",
		"BEFORE UPDATE OR DELETE ON edge_publication_serving_nodes",
		"REVOKE ALL ON FUNCTION protect_edge_publication_serving_nodes_702() FROM PUBLIC;",
		"GRANT SELECT, INSERT ON edge_publication_serving_nodes TO cdnca_control_app, cdnca_control_runtime;",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("702 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 702",
		"migration_id='702_edge_publication_serving_nodes'", "ERRCODE='P7020'",
		"DROP TABLE edge_publication_serving_nodes;", "DROP FUNCTION protect_edge_publication_serving_nodes_702();",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("702 down missing %q", fragment)
		}
	}
}
