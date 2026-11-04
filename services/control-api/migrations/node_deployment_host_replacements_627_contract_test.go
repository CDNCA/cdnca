package migrations

import (
	"strings"
	"testing"
)

// Migration 627 (on top of 626 node_metric_host_epoch):
// a deployment created before the node's newest enrollment may end as failed
// on a node_deployment_host_replacements fact (edgedeployment.
// CloseReplacedHostDeploymentsTx). The 046 trigger names stay, pointed at the
// _627 functions; the 046 functions are not changed.
func TestNodeDeploymentHostReplacements627Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"627_node_deployment_host_replacements.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 626", "(SELECT max(version) FROM schema_migrations) <> 626",
			"migration_id='626_node_metric_host_epoch'", "ERRCODE='P6270'",
			"CREATE TABLE node_deployment_host_replacements", "reason_code text NOT NULL CHECK (reason_code = 'host_replaced')",
			"'activated', 'reverting')", "REFERENCES node_deployments (id, attempt) ON DELETE CASCADE",
			"REFERENCES node_certificates (id, node_id) ON DELETE CASCADE",
			"enrollment.issuance_kind = 'initial' AND enrollment.issued_at > deployment.created_at",
			"ERRCODE='P6273'", "ERRCODE='P6274'", "WHEN (NOT node_purge_in_progress())",
			"CREATE FUNCTION enforce_node_deployment_state_627()", "CREATE FUNCTION assert_node_deployment_fact_627()",
			"FROM node_deployment_host_replacements replaced",
			"CREATE TRIGGER node_deployments_state_046\nBEFORE UPDATE OF state ON node_deployments\nFOR EACH ROW EXECUTE FUNCTION enforce_node_deployment_state_627();",
			"CREATE CONSTRAINT TRIGGER node_deployments_fact_046\nAFTER INSERT OR UPDATE OF state ON node_deployments\nDEFERRABLE INITIALLY DEFERRED\nFOR EACH ROW EXECUTE FUNCTION assert_node_deployment_fact_627();",
		}, []string{"CREATE OR REPLACE FUNCTION enforce_node_deployment_state_046", "CREATE OR REPLACE FUNCTION assert_node_deployment_fact_046",
			"DROP FUNCTION", "UPDATE node_deployments", "DELETE FROM"}},
		{"627_node_deployment_host_replacements.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 627", "migration_id='627_node_deployment_host_replacements'",
			"ERRCODE='P6271'", "IF EXISTS (SELECT 1 FROM node_deployment_host_replacements)", "ERRCODE='P6272'",
			"FOR EACH ROW EXECUTE FUNCTION enforce_node_deployment_state_046();",
			"FOR EACH ROW EXECUTE FUNCTION assert_node_deployment_fact_046();",
			"DROP FUNCTION assert_node_deployment_fact_627();", "DROP FUNCTION enforce_node_deployment_state_627();",
			"DROP TABLE node_deployment_host_replacements;",
		}, []string{"DROP FUNCTION enforce_node_deployment_state_046", "DROP FUNCTION assert_node_deployment_fact_046",
			"DELETE FROM", "UPDATE node_deployments"}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
}
