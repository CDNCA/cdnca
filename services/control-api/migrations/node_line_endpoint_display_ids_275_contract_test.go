package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodeLineEndpointDisplayIDs275Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"275_node_line_endpoint_display_ids.up.sql", "4bad15845ee9443d6549666f558c0b2fb70437cc63e09ee718db4bfb3d26c214", []string{
			"LOCK TABLE schema_migrations, node_line_endpoints IN ACCESS EXCLUSIVE MODE",
			"274_node_line_endpoint_sort_order", nodeLineEndpointSortOrder274UpSHA, nodeLineEndpointSortOrder274DownSHA,
			"GENERATED ALWAYS AS IDENTITY", "PRIMARY KEY(tenant_scope_id, line_group_id, endpoint_id)",
			"GROUP BY tenant_scope_id,line_group_id,id", "SECURITY DEFINER SET search_path = pg_catalog, pg_temp",
			"ON CONFLICT(tenant_scope_id,line_group_id,endpoint_id) DO NOTHING", "ERRCODE='P2751'",
			"BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE", "GRANT SELECT ON node_line_endpoint_display_ids TO cdnca_control_app",
		}},
		{"275_node_line_endpoint_display_ids.down.sql", "17f22069d8b7ed032746b58721975df0aec2fe6e46571036f417ffa6767c289e", []string{
			"(SELECT count(*) FROM schema_migrations) <> 275", "275_node_line_endpoint_display_ids",
			"IF EXISTS (SELECT 1 FROM node_line_endpoint_display_ids)", "ERRCODE='P2752'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
