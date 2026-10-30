package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodePresenceScopeIdentities290Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"290_node_presence_scope_identities.up.sql", "cb0d58a1540732697ee07343fa46b4f332ead7b2b3ce4f17996815c82e0e0ae2", []string{
			"(SELECT count(*) FROM schema_migrations) <> 289", "289_node_deployment_agent_queue",
			"9d8ae1ddf95d2294fd325de2dde4a338bb651c6d157dcbc31500723abbff74b6", "ERRCODE='P2900'",
			"CREATE TABLE node_presence_scope_identities",
			"REFERENCES node_config_state (node_id, configuration_scope_id)",
			"validate_node_presence_scope_identity_290", "active_config_identity_artifact_valid_087",
		}},
		{"290_node_presence_scope_identities.down.sql", "2f84c4a265c19802604434c6dd50a168b0c3b0a7bb98158171bbb44daf8cd7c1", []string{
			"(SELECT count(*) FROM schema_migrations) <> 290", "290_node_presence_scope_identities",
			"ERRCODE='P2901'", "DROP TABLE node_presence_scope_identities",
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
