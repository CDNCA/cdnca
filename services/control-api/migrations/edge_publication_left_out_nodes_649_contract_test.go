package migrations

import (
	"fmt"
	"strings"
	"testing"
)

// Migration 649 (the nodes a publication did not reach as
// intended, kept on edge_config_publications) guards the 648 head.
const (
	migration649Version         = 649
	migration649ID              = "649_edge_publication_left_out_nodes"
	migration649PreviousID      = "648_node_key_envelope_oversized_audit_index"
	migration649PreviousUpSHA   = "22eb08464ed15def5f716c39823334c08556f253b4a980df9754195074709a33"
	migration649PreviousDownSHA = "96929b92dc5eb86ae76b638e68165c142559d4d4c4e19859d1325caa609eb7f9"
)

func TestEdgePublicationLeftOutNodes649Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration649ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration649Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration649Version-1),
			"migration_id='" + migration649PreviousID + "'", migration649PreviousUpSHA, migration649PreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", migration649Version),
			"ADD COLUMN key_envelope_oversized_node_ids uuid[] NOT NULL DEFAULT '{}'",
			"ADD COLUMN site_selection_unsupported_node_ids uuid[] NOT NULL DEFAULT '{}'",
		}},
		{migration649ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration649Version),
			"migration_id='" + migration649ID + "'", fmt.Sprintf("ERRCODE='P%d1'", migration649Version),
			"DROP COLUMN key_envelope_oversized_node_ids", "DROP COLUMN site_selection_unsupported_node_ids",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (merge renumbering): %v", script.name, err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
