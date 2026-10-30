package migrations

import (
	"strings"
	"testing"
)

func TestNodeMonitoringCommandOutboxTriggerFix268Contract(t *testing.T) {
	up, err := FS.ReadFile("268_node_monitoring_command_outbox_trigger_fix.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("268_node_monitoring_command_outbox_trigger_fix.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 268 requires the exact verified 267 release head and node monitoring outbox trigger",
		"CREATE OR REPLACE FUNCTION protect_node_monitoring_command_outbox()",
		"IF TG_OP = 'UPDATE' THEN",
		"RAISE EXCEPTION 'node monitoring command outbox identity is immutable'",
		"IF TG_OP = 'INSERT' THEN",
		"RAISE EXCEPTION 'invalid initial node monitoring command outbox state'",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration 268 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 268 rollback requires the exact verified 268 release head",
		"migration 268 rollback is blocked to retain the corrected node monitoring outbox trigger",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("migration 268 down is missing %q", required)
		}
	}
}
