package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 348 (overdue node deployments end as failed)
// is a placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is in this block.
const (
	migration348Version         = 348
	migration348ID              = "348_node_deployment_timeouts"
	migration348PreviousID      = "347_acme_http01_epoch_drift_alerts"
	migration348PreviousUpSHA   = "53250a2b680900c2d6359e7b42de9cc30bfc6ab45363647c140299cc0a5ecb9a"
	migration348PreviousDownSHA = "71aaf1239c64112034810e49f68af26f6684a25bcfdfaa74bfe426d45156939e"
	migration348UpSHA           = "1073378383d2e63d4858913f637c54be738e2af70f73b0332e1176ed9f8b9a01"
	migration348DownSHA         = "4066592c54f6f32b66fcd091d2c377e3cc11519d2c6c41c5cfec555cd57f2214"
)

func TestNodeDeploymentTimeouts348Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration348ID + ".up.sql", migration348UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration348Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration348Version-1),
			"migration_id='" + migration348PreviousID + "'", migration348PreviousUpSHA, migration348PreviousDownSHA,
			"ERRCODE='P3480'", "CREATE TABLE node_deployment_timeouts",
			"CHECK (timed_out_at >= deadline_at + interval '1 minute')",
			"CREATE FUNCTION guard_node_deployment_timeout_348()", "ERRCODE='P3483'", "ERRCODE='P3484'",
			"REVOKE ALL ON FUNCTION guard_node_deployment_timeout_348() FROM PUBLIC",
			"CREATE TRIGGER node_deployment_timeouts_guard_348", "CREATE TRIGGER zz_core_fact_truncate_guard_348",
			"CREATE INDEX node_deployments_timeout_due_348_idx",
			"GRANT SELECT, INSERT ON node_deployment_timeouts TO cdnca_control_app, cdnca_control_runtime",
			"CREATE OR REPLACE FUNCTION enforce_node_deployment_state_046()",
			"CREATE OR REPLACE FUNCTION assert_node_deployment_fact_046()",
			"timeout.previous_state = 'queued'", "timeout.previous_state = OLD.state",
		}},
		{migration348ID + ".down.sql", migration348DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration348Version),
			"migration_id='" + migration348ID + "'", "ERRCODE='P3481'", "ERRCODE='P3482'",
			"CREATE OR REPLACE FUNCTION enforce_node_deployment_state_046()",
			"CREATE OR REPLACE FUNCTION assert_node_deployment_fact_046()",
			"DROP INDEX node_deployments_timeout_due_348_idx", "DROP TABLE node_deployment_timeouts",
			"DROP FUNCTION guard_node_deployment_timeout_348()",
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
	// The down restores exactly the functions 289 and 046 left: no node
	// deployment may fail through a timeout once the table is gone.
	down, err := FS.ReadFile(migration348ID + ".down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(down), "node_deployment_timeouts timeout") {
		t.Error("348 down still consults node_deployment_timeouts in a restored trigger")
	}
}
