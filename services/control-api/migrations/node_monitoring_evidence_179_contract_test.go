package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestNODE07NodeMonitoringEvidence179Contract(t *testing.T) {
	predecessorUp := readNodeMonitoringMigration(t, "178_system_configuration_edge_publication.up.sql")
	predecessorDown := readNodeMonitoringMigration(t, "178_system_configuration_edge_publication.down.sql")
	upBytes := readNodeMonitoringMigration(t, "179_node_monitoring_evidence.up.sql")
	downBytes := readNodeMonitoringMigration(t, "179_node_monitoring_evidence.down.sql")
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 179 requires the exact verified 178 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)), fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"ADD COLUMN record_kind text NOT NULL DEFAULT 'legacy_metric'",
		"ALTER COLUMN record_kind DROP DEFAULT",
		"node_metric_samples_record_shape_179", "record_kind='metric'",
		"record_kind='recovery_notification'", "recovery_reason_code='probe_recovered'",
		"CREATE OR REPLACE VIEW node_metric_latest", "WHERE record_kind='metric'",
		"CREATE VIEW node_recovery_latest", "WHERE record_kind='recovery_notification'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("179 up missing %q", required)
		}
	}
	guard := strings.Index(up, "migration 179 requires the exact verified 178 release head")
	mutation := strings.Index(up, "ALTER TABLE node_metric_samples\n    ADD COLUMN")
	if guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("179 predecessor guard must run before the first schema mutation")
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 179 rollback requires the exact verified 179 head", upSHA,
		"record_kind<>'legacy_metric'",
		"rollback would discard durable node monitoring probe or recovery evidence",
		"DROP VIEW node_recovery_latest", "DROP COLUMN record_kind",
		"CREATE VIEW node_metric_latest",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("179 down missing %q", required)
		}
	}
}

func readNodeMonitoringMigration(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
