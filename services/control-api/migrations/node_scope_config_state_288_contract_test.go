package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodeScopeConfigState288Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"288_node_scope_config_state.up.sql", "2064bbd569ac159ed70c69691a62aff1986484205589e2dd742cab689cfa3c84", []string{
			"(SELECT count(*) FROM schema_migrations) <> 287", "287_tenant_node_carriage",
			"92f74575dc1f67555becf5b46e120c9e40c994f244fceee147b41ee071f00440", "ERRCODE='P2880'",
			"PRIMARY KEY (node_id, configuration_scope_id)", "node_config_state_single_scope_288_idx",
			"bind_node_deployment_scope_288", "node_deployments_one_active_per_node_scope_288_idx",
			// Isolation binds the node's owner scope, not a tenant's configuration.
			"node_isolation_states_desired_config_288_fkey", "CREATE OR REPLACE FUNCTION protect_node_isolation_state_182()",
		}},
		{"288_node_scope_config_state.down.sql", "b2661e04bcd03edadc8468a3fca241330180e2e857f41981bad48465598ba140", []string{
			"(SELECT count(*) FROM schema_migrations) <> 288", "288_node_scope_config_state",
			// Several scopes on one node cannot be folded back silently.
			"ERRCODE='P2881'", "HAVING count(*) > 1", "ADD CONSTRAINT node_config_state_pkey PRIMARY KEY (node_id)",
			"node_isolation_states_scope_id_desired_config_version_id_fkey",
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
