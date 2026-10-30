package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestBILL07PackagePeriodReset164Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("163_account_registration_challenge.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("163_account_registration_challenge.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("164_package_period_reset.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("164_package_period_reset.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	predecessorUpSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorUp))
	predecessorDownSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorDown))
	for _, required := range []string{
		"migration 164 requires a contiguous verified 163 release head",
		"version=163 AND migration_id='163_account_registration_challenge'", predecessorUpSHA, predecessorDownSHA,
		"CREATE TABLE package_period_reset_claims_164", "CREATE TABLE package_period_reset_facts_164",
		"CREATE TABLE package_period_reset_recovery_outbox_164",
		"UNIQUE(tenant_scope_id,subscription_id,target_reset_key)",
		"REFERENCES package_cycle_enforcement_heads(tenant_scope_id,subscription_id)",
		"prior_adjustment_count integer NOT NULL", "REFERENCES background_jobs(id)",
		"state IN ('claimed','completed')", "lease_id uuid NOT NULL", "request_id text NOT NULL",
		"recovery_authorized boolean NOT NULL", "recovery_job_count integer NOT NULL",
		"prevent_package_period_reset_fact_mutation_164", "package_period_reset_claim_single_winner_164",
		"NEW.lease_expires_at<=OLD.lease_expires_at",
		"ROW(NEW.worker_id,NEW.lease_id,NEW.lease_expires_at) IS DISTINCT FROM",
		"ROW(OLD.worker_id,OLD.lease_id,OLD.lease_expires_at)",
		"REVOKE ALL ON package_period_reset_claims_164",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("164 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 164 requires a contiguous verified 163 release head"),
		strings.Index(up, "CREATE TABLE package_period_reset_claims_164"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("164 predecessor guard must precede the first schema mutation")
	}
	for _, forbidden := range []string{"DELETE FROM package_cycle_usage_adjustments", "CASCADE", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("164 migration contains forbidden marker %q", forbidden)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 164 rollback requires the exact verified 164 head",
		"version=164 AND migration_id='164_package_period_reset'", upSHA,
		"migration 164 rollback would discard package period reset facts",
		"DROP TABLE package_period_reset_recovery_outbox_164",
		"DROP TABLE package_period_reset_facts_164", "DROP TABLE package_period_reset_claims_164",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("164 down missing %q", required)
		}
	}
}
