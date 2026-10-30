package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestMultiTenantNodeGate291Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"291_multi_tenant_node_gate.up.sql", "c843962a9696c76cd1038ad51bbc23d13069dcfb231584098827e307142dd559", []string{
			"(SELECT count(*) FROM schema_migrations) <> 290", "290_node_presence_scope_identities",
			"cb0d58a1540732697ee07343fa46b4f332ead7b2b3ce4f17996815c82e0e0ae2", "ERRCODE='P2910'",
			"DROP INDEX node_config_state_single_scope_288_idx", "queued_per_scope",
			"node_deployments_one_active_unqueued_per_node_291_idx",
			"configuration_scope_id = NEW.configuration_scope_id", "state.configuration_scope_id=NEW.scope_id",
		}},
		{"291_multi_tenant_node_gate.down.sql", "58a6a8dd74b355db9b043b48d62f536704904c96c74db0cb3017e61df038e488", []string{
			"(SELECT count(*) FROM schema_migrations) <> 291", "291_multi_tenant_node_gate",
			// Several scopes on one node cannot be folded back silently.
			"ERRCODE='P2911'", "HAVING count(*) > 1", "CREATE UNIQUE INDEX node_deployments_one_active_per_node_idx",
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
