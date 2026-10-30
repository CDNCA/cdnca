package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestNODE08PortTransition180Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("179_node_monitoring_evidence.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("179_node_monitoring_evidence.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("180_node_gateway_port_transitions.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("180_node_gateway_port_transitions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 180 requires the exact verified 179 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)), fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"CREATE TABLE node_gateway_port_transitions", "expected_node_revision", "compatibility_deadline",
			"rollback_deadline", "certificate_sha256", "status_revision", "active_endpoint",
			"node_gateway_port_transition_command_outbox", "payload_sha256", "claim_token", "puback_sequence",
			"node_gateway_port_transition_status_events", "UNIQUE (transition_id,status_revision)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("180 up missing %q", required)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 180 rollback requires the exact verified 180 head", upSHA,
		"rollback would discard durable gateway port transition evidence",
			"DROP TABLE node_gateway_port_transition_status_events", "DROP TABLE node_gateway_port_transition_command_outbox",
			"DROP TABLE node_gateway_port_transitions",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("180 down missing %q", required)
		}
	}
}
