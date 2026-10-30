package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestIAM02AccountRegistrationProof162Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("161_recharge_identity_eligibility.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("161_recharge_identity_eligibility.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("162_account_registration_proof.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("162_account_registration_proof.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	predecessorUpSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorUp))
	predecessorDownSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorDown))
	for _, required := range []string{
		"migration 162 requires a contiguous verified 161 release head",
		"version=161 AND migration_id='161_recharge_identity_eligibility'", predecessorUpSHA, predecessorDownSHA,
		"CREATE TABLE account_registration_proofs_162", "reference_digest bytea", "evidence_id uuid",
		"channel text", "destination_digest bytea", "subject_digest bytea", "source_digest bytea",
		"risk_context text", "human_verified_at timestamptz", "contact_verified_at timestamptz",
		"expires_at timestamptz", "attempt_revision bigint", "use_revision bigint",
		"consumed_idempotency_digest bytea", "consumed_binding_digest bytea", "consumed_at timestamptz",
		"UNIQUE (reference_digest)", "REVOKE ALL ON account_registration_proofs_162 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("162 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 162 requires a contiguous verified 161 release head"),
		strings.Index(up, "CREATE TABLE account_registration_proofs_162"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("162 predecessor guard must precede the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 162 rollback requires the exact verified 162 head",
		"version=162 AND migration_id='162_account_registration_proof'", upSHA,
		"version=161 AND migration_id='161_recharge_identity_eligibility'", predecessorUpSHA, predecessorDownSHA,
		"migration 162 rollback would discard account registration proof facts",
		"DROP TABLE account_registration_proofs_162",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("162 down missing %q", required)
		}
	}
	if refusal, drop := strings.Index(down, "migration 162 rollback would discard account registration proof facts"),
		strings.Index(down, "DROP TABLE account_registration_proofs_162"); refusal < 0 || drop < 0 || refusal > drop {
		t.Fatal("162 fact refusal must precede destructive rollback")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("162 migration contains forbidden marker %q", forbidden)
		}
	}
}
