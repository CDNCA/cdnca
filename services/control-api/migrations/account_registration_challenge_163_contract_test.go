package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestIAM02AccountRegistrationChallenge163Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("162_account_registration_proof.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("162_account_registration_proof.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("163_account_registration_challenge.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("163_account_registration_challenge.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	predecessorUpSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorUp))
	predecessorDownSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorDown))
	for _, required := range []string{
		"migration 163 requires a contiguous verified 162 release head",
		"version=162 AND migration_id='162_account_registration_proof'", predecessorUpSHA, predecessorDownSHA,
		"CREATE TABLE account_registration_challenge_writes_163", "human_token_digest bytea",
		"UNIQUE (human_token_digest)", "CREATE TABLE account_registration_challenges_163",
		"otp_digest bytea", "failed_attempts integer", "max_attempts integer", "attempt_revision bigint",
		"CREATE TABLE account_registration_challenge_verify_receipts_163",
		"CREATE TABLE account_registration_challenge_dispatch_claims_163",
		"sealed_payload bytea", "destination_digest bytea", "anonymous_dispatch_reference uuid",
		"REVOKE ALL ON account_registration_challenges_163 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("163 up missing %q", required)
		}
	}
	for _, forbidden := range []string{"otp text", "destination text", "human_token text", "CASCADE", "DELETE FROM schema_migrations"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("163 migration contains forbidden marker %q", forbidden)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 163 rollback requires the exact verified 163 head",
		"version=163 AND migration_id='163_account_registration_challenge'", upSHA,
		"migration 163 rollback would discard account registration challenge facts",
		"DROP TABLE account_registration_challenge_dispatch_claims_163",
		"DROP TABLE account_registration_challenge_verify_receipts_163",
		"DROP TABLE account_registration_challenges_163",
		"DROP TABLE account_registration_challenge_writes_163",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("163 down missing %q", required)
		}
	}
}
