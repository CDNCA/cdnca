package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestNODE06NodeTrafficPolicies181Contract(t *testing.T) {
	predecessorUp := readNodeTrafficMigration(t, "180_node_gateway_port_transitions.up.sql")
	predecessorDown := readNodeTrafficMigration(t, "180_node_gateway_port_transitions.down.sql")
	upBytes := readNodeTrafficMigration(t, "181_node_traffic_policies.up.sql")
	downBytes := readNodeTrafficMigration(t, "181_node_traffic_policies.down.sql")
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 181 requires the exact verified 180 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"CREATE TABLE node_traffic_policies",
		"monthly_limit_bytes",
		"next_evaluation_at",
		"last_evaluation_error",
		"CREATE TABLE node_traffic_policy_operations",
		"CREATE TABLE node_traffic_policy_evaluations",
		"source_finalized_through",
		"source_digest",
		"CREATE TABLE node_traffic_sync_tasks",
		"REFERENCES node_traffic_policy_evaluations(id,scope_id,node_id)",
		"REFERENCES config_versions(configuration_scope_id,id)",
		"REFERENCES rollouts(configuration_scope_id,id)",
		"REFERENCES rollouts(id,config_version_id)",
		"node traffic policy operation and evaluation evidence is append-only",
		"node traffic sync task must bind the current node configuration",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("181 up missing %q", required)
		}
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 181 rollback requires the exact verified 181 head",
		upSHA,
		"rollback would discard durable node traffic policy or sync evidence",
		"DROP TABLE node_traffic_sync_tasks",
		"DROP TABLE node_traffic_policy_evaluations",
		"DROP TABLE node_traffic_policy_operations",
		"DROP TABLE node_traffic_policies",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("181 down missing %q", required)
		}
	}
}

func readNodeTrafficMigration(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
