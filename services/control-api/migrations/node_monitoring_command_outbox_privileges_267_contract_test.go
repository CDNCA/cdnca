package migrations

import (
	"strings"
	"testing"
)

func TestNodeMonitoringCommandOutboxPrivileges267Contract(t *testing.T) {
	up, err := FS.ReadFile("267_node_monitoring_command_outbox_privileges.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("267_node_monitoring_command_outbox_privileges.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 267 requires the exact verified 266 release head",
		"GRANT SELECT, INSERT, UPDATE ON node_monitoring_command_outbox TO cdnca_control_runtime",
		"GRANT EXECUTE ON FUNCTION protect_node_monitoring_command_outbox() TO cdnca_control_runtime",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration 267 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 267 rollback requires the exact verified 267 release head",
		"REVOKE SELECT, INSERT, UPDATE ON node_monitoring_command_outbox FROM cdnca_control_runtime",
		"REVOKE EXECUTE ON FUNCTION protect_node_monitoring_command_outbox() FROM cdnca_control_runtime",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("migration 267 down is missing %q", required)
		}
	}
}
