package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	migration118UpSHA119   = "7190a136a8c7685eb20538f86c67541a183d5631b9924d16aeb2cba511a72499"
	migration118DownSHA119 = "a9535f404e8f4630bb1c0c02fca4c3ace0612021ca023603fe6ac9af76be5f1a"
)

func TestCacheCancelledReportFacts119Contract(t *testing.T) {
	up := readMigration119(t, "119_cache_cancelled_report_facts.up.sql")
	down := readMigration119(t, "119_cache_cancelled_report_facts.down.sql")
	upSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	assertMigrationSHA119(t, "118_certificate_publication_claims.up.sql", migration118UpSHA119)
	assertMigrationSHA119(t, "118_certificate_publication_claims.down.sql", migration118DownSHA119)

	for _, required := range []string{
		"migration 119 requires the exact verified 118 release head",
		"migration_id='118_certificate_publication_claims'",
		"checksum_sha256='" + migration118UpSHA119 + "'",
		"down_checksum_sha256='" + migration118DownSHA119 + "'",
		"DROP CONSTRAINT cache_operation_node_attempts_check1",
		"ADD CONSTRAINT cache_operation_node_attempts_report_state_check",
		"state IN ('succeeded','partial_failed','failed','cancelled') AND report_sequence>0",
		"DROP CONSTRAINT cache_operation_target_results_check",
		"ADD CONSTRAINT cache_operation_target_results_source_state_check",
		"source='report' AND attempt IS NOT NULL AND state IN ('succeeded','failed','cancelled')",
		"state='cancelled' AND error_code='cancelled'",
		"CREATE OR REPLACE FUNCTION validate_cache_operation_integrity()",
		"WHEN attempt.state='cancelled' AND attempt.report_sequence>0 THEN 'report'",
		"operation_row.state='partial_failed'",
		"actual_failed+actual_cancelled",
	} {
		if !strings.Contains(compactSQL119(up), compactSQL119(required)) {
			t.Errorf("119 up missing %q", required)
		}
	}
	guard := strings.Index(up, "migration 119 requires the exact verified 118 release head")
	mutation := strings.Index(up, "ALTER TABLE cache_operation_node_attempts")
	if guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("119 predecessor guard must precede the first mutation")
	}

	for _, required := range []string{
		"migration 119 rollback requires the exact verified 119 head",
		"checksum_sha256='" + upSHA + "'",
		"rollback would discard agent-reported cache cancellation facts",
		"source='report' AND state='cancelled'",
		"state='cancelled' AND report_sequence>0",
		"DROP CONSTRAINT cache_operation_node_attempts_report_state_check",
		"DROP CONSTRAINT cache_operation_target_results_source_state_check",
		"CREATE OR REPLACE FUNCTION validate_cache_operation_integrity()",
	} {
		if !strings.Contains(compactSQL119(down), compactSQL119(required)) {
			t.Errorf("119 down missing %q", required)
		}
	}
	factGuard := strings.Index(down, "rollback would discard agent-reported cache cancellation facts")
	firstMutation := strings.Index(down, "ALTER TABLE cache_operation_node_attempts")
	if factGuard < 0 || firstMutation < 0 || factGuard > firstMutation {
		t.Fatal("119 rollback fact guard must precede the first mutation")
	}
}

func readMigration119(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func assertMigrationSHA119(t *testing.T, name, want string) {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(content)); got != want {
		t.Fatalf("%s SHA-256=%s, want %s", name, got, want)
	}
}

func compactSQL119(value string) string {
	return strings.Join(strings.Fields(value), "")
}
