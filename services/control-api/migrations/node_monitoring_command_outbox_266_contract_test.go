package migrations

import (
	"strings"
	"testing"
)

func TestNodeMonitoringCommandOutbox266Contract(t *testing.T) {
	up, err := FS.ReadFile("266_node_monitoring_command_outbox.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("266_node_monitoring_command_outbox.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 266 requires the exact verified 265 release head",
		"CREATE TABLE node_monitoring_command_outbox",
		"UNIQUE (node_id, config_revision)",
		"NODE_MONITORING_COMMANDS",
		"protect_node_monitoring_command_outbox",
		"claimed_until",
		"(claim_token IS NULL) = (claimed_until IS NULL)",
		"(puback_stream IS NULL) = (puback_sequence IS NULL)",
		"published_at IS NULL OR state = 'published'",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration 266 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 266 rollback requires the exact verified 266 release head",
		"migration 266 rollback would discard node monitoring command facts",
		"DROP TABLE node_monitoring_command_outbox",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("migration 266 down is missing %q", required)
		}
	}
}
