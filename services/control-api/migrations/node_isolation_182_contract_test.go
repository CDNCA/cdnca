package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestNODE09NodeIsolation182Contract(t *testing.T) {
	predecessorUp := readNodeIsolationMigration(t, "181_node_traffic_policies.up.sql")
	predecessorDown := readNodeIsolationMigration(t, "181_node_traffic_policies.down.sql")
	upBytes := readNodeIsolationMigration(t, "182_node_isolation.up.sql")
	downBytes := readNodeIsolationMigration(t, "182_node_isolation.down.sql")
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 182 requires the exact verified 181 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"CREATE TABLE node_isolation_states",
		"desired_config_version_id",
		"desired_artifact_sha256",
		"desired_identity_schema",
		"consecutive_failures",
		"last_session_epoch",
		"last_health_sequence",
		"CREATE TABLE node_isolation_reports",
		"request_digest",
		"CREATE TABLE node_isolation_alert_events",
		"node_config_sync_isolated",
		"node_config_sync_recovered",
		"node isolation state must bind the current node configuration identity",
		"node isolation state identity, revision, time, and health evidence are monotonic",
		"node isolation report and alert evidence is append-only",
		"REFERENCES nodes(scope_id,id)",
		"REFERENCES config_versions(configuration_scope_id,id)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("182 up missing %q", required)
		}
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 182 rollback requires the exact verified 182 head",
		upSHA,
		"rollback would discard durable node isolation state, report, or alert evidence",
		"DROP TABLE node_isolation_alert_events",
		"DROP TABLE node_isolation_reports",
		"DROP TABLE node_isolation_states",
		"DROP FUNCTION reject_node_isolation_evidence_mutation_182()",
		"DROP FUNCTION protect_node_isolation_state_182()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("182 down missing %q", required)
		}
	}
}

func readNodeIsolationMigration(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
