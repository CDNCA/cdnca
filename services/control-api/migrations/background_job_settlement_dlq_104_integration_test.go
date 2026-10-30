//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestBackgroundJobSettlementDLQ104MigrationContract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("104_background_job_settlement_dlq.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("104_background_job_settlement_dlq.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 104 requires the exact verified 103 release head",
		"103_certificate_renewal_retry_after_failed_child",
		"356d6bbee4f13cd68df4958156fc175663c500bf2c644630d35f8e5568483cf6",
		"f7b6f88df56dbac6689bbc441bde80d6ab41a5eb8cf7af498778b5f25608b2ca",
		"down_checksum_sha256",
		"CREATE TABLE background_job_dead_letters",
		"CREATE TABLE background_job_replay_facts",
		"background job dead letters are append-only",
		"background job replay facts are append-only",
		"operation IN ('cancel','retry','replay')",
		"DROP CONSTRAINT background_job_command_receipts_check3",
		"ADD CONSTRAINT background_job_command_receipts_result_check_104",
		"NEW.operation = 'replay' AND NEW.audience <> 'platform'",
		"job.replay",
		"pg_current_xact_id()",
		"CREATE OR REPLACE FUNCTION protect_background_job()",
		"REVOKE ALL ON background_job_dead_letters FROM PUBLIC",
		"REVOKE ALL ON background_job_replay_facts FROM PUBLIC",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("104 up missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 104 rollback requires the exact verified 104 head",
		"migration 104 rollback would discard settlement or replay facts",
		"DROP TABLE background_job_replay_facts",
		"DROP TABLE background_job_dead_letters",
		"DROP CONSTRAINT background_job_command_receipts_result_check_104",
		"ADD CONSTRAINT background_job_command_receipts_check3",
		"operation IN ('cancel','retry')",
		"CREATE OR REPLACE FUNCTION protect_background_job()",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("104 down missing %q", required)
		}
	}
}
