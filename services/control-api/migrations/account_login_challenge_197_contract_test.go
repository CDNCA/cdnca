package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestAccountLoginChallenge197Contract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("197_account_login_challenge.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("197_account_login_challenge.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(up) + string(down)
	for _, required := range []string{
		"version=196 AND migration_id='196_platform_system_other_settings'",
		"296e9eb4404dc60f37b3564e960fa6194ad8ae7b0cd41925fc5c64c26feed011",
		"8d2af779e2da3218c17f063de6fd6e99f60838994a16ee120dbcf9966a992eb7",
		"CREATE TABLE account_login_challenge_writes_197",
		"CREATE TABLE account_login_challenges_197",
		"CREATE TABLE account_login_challenge_verify_receipts_197",
		"CREATE TABLE account_login_challenge_dispatch_claims_197",
		"identity.account_login_verification",
		"migration 197 rollback requires the exact unused verified release head",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("197 migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"otp text", "destination text", "CASCADE", "DELETE FROM schema_migrations"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("197 migration contains forbidden %q", forbidden)
		}
	}
}
