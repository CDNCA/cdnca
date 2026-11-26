package migrations

import (
	"strings"
	"testing"
)

// Migration 700: on the verified 699 head, a create of a node
// upgrade rollout records one control_upgrade_create_preparations row per 096 create intent; a
// background worker claims it with a lease, issues the License artifacts, downloads both artifacts
// and finalizes the plan. failed and ready are terminal and the row identity is immutable. Down
// drops the table and its trigger function.
func TestControlUpgradeCreatePreparations700Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := read("700_control_upgrade_create_preparations.up.sql")
	down := read("700_control_upgrade_create_preparations.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, control_upgrade_grant_intents_096 IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 699", "(SELECT max(version) FROM schema_migrations) <> 699",
		"WHERE version=699 AND", "migration_id='699_billing_bridge_log_request_id'", "ERRCODE='P7003'",
		"intent_id uuid PRIMARY KEY REFERENCES control_upgrade_grant_intents_096(id) ON DELETE RESTRICT",
		"plan_id uuid NOT NULL UNIQUE",
		"state text NOT NULL CHECK (state IN ('preparing','failed','ready'))",
		"phase text NOT NULL CHECK (phase IN ('queued','issuing','downloading','finalizing','starting','done'))",
		"start_when_ready boolean NOT NULL,",
		"'approval_required','start_refused',",
		"CHECK (phase<>'starting' OR start_when_ready)",
		"CHECK (start_failure_code IS NULL OR (state='ready' AND start_when_ready))",
		"WHERE state<>'ready' OR start_failure_code IS NOT NULL;",
		"NEW.start_when_ready,NEW.created_at",
		"'license_unavailable','license_outcome_unknown','license_rejected','grant_invalid',",
		"'artifact_download_failed','artifact_invalid','cohort_incompatible','permission_denied',",
		"'resource_unavailable','internal_error'",
		"CHECK ((state='failed') = (failure_code IS NOT NULL))",
		"CHECK (failure_reason IS NULL OR failure_code IS NOT DISTINCT FROM 'license_rejected' OR\n        start_failure_code IS NOT DISTINCT FROM 'license_rejected')",
		"CHECK ((state='ready') = (phase='done'))",
		"CHECK (state='preparing' OR claim_token IS NULL)",
		"WHERE state='preparing';",
		"IF OLD.state<>'preparing' THEN", "ERRCODE='P7005'",
		"BEFORE UPDATE OR DELETE ON control_upgrade_create_preparations",
		"BEFORE TRUNCATE ON control_upgrade_create_preparations",
		"REVOKE ALL ON TABLE control_upgrade_create_preparations FROM PUBLIC;",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("700 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 700",
		"migration_id='700_control_upgrade_create_preparations'", "ERRCODE='P7004'",
		"DROP TABLE control_upgrade_create_preparations;",
		"DROP FUNCTION validate_control_upgrade_create_preparation_700();",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("700 down missing %q", fragment)
		}
	}
	if strings.Index(down, "DROP TABLE") > strings.Index(down, "DROP FUNCTION") {
		t.Error("700 down drops the trigger function before its table")
	}
}
