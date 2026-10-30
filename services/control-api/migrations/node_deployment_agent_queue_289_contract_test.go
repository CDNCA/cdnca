package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodeDeploymentAgentQueue289Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"289_node_deployment_agent_queue.up.sql", "9d8ae1ddf95d2294fd325de2dde4a338bb651c6d157dcbc31500723abbff74b6", []string{
			"(SELECT count(*) FROM schema_migrations) <> 288", "288_node_scope_config_state",
			"2064bbd569ac159ed70c69691a62aff1986484205589e2dd742cab689cfa3c84", "ERRCODE='P2890'",
			"node_deployments_state_289", "deployment_status_events_state_289",
			"OLD.state = 'agent_queued' AND NEW.state IN ('started', 'failed')",
		}},
		{"289_node_deployment_agent_queue.down.sql", "125c561a5978826554cbd621bfc83e500d8cb5fb86bb99d556f3f31512ec4f72", []string{
			"(SELECT count(*) FROM schema_migrations) <> 289", "289_node_deployment_agent_queue",
			// Recorded agent queue facts are never rewritten on rollback.
			"ERRCODE='P2891'", "ADD CONSTRAINT node_deployments_state_046",
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
