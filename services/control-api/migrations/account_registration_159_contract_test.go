package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestIAM02AccountRegistration159Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("158_ja4_block_edge_receipts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("158_ja4_block_edge_receipts.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("159_account_registration.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("159_account_registration.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	predecessorUpSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorUp))
	predecessorDownSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorDown))
	for _, required := range []string{
		"migration 159 requires a contiguous verified 158 release head",
		"version=158 AND migration_id='158_ja4_block_edge_receipts'", predecessorUpSHA, predecessorDownSHA,
		"CREATE UNIQUE INDEX users_email_registration_unique_159",
		"CREATE UNIQUE INDEX users_phone_registration_unique_159",
		"CREATE TABLE account_registration_requests_159",
		"CREATE TABLE account_registration_terms_159",
		"CREATE TABLE account_registration_verification_intents_159",
		"UNIQUE(idempotency_key)", "octet_length(request_digest)=32", "octet_length(subject_digest)=32",
		"state IN ('pending','completed')", "outcome IN ('created','duplicate')",
		"verification_channel IN ('email','sms')", "BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE",
		"REVOKE ALL ON account_registration_requests_159 FROM PUBLIC",
		"REVOKE ALL ON account_registration_terms_159 FROM PUBLIC",
		"REVOKE ALL ON account_registration_verification_intents_159 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("159 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 159 requires a contiguous verified 158 release head"),
		strings.Index(up, "CREATE UNIQUE INDEX users_email_registration_unique_159"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("159 predecessor guard must precede the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 159 rollback requires the exact verified 159 head",
		"version=159 AND migration_id='159_account_registration'", upSHA,
		"version=158 AND migration_id='158_ja4_block_edge_receipts'", predecessorUpSHA, predecessorDownSHA,
		"migration 159 rollback would discard account registration facts",
		"DROP TABLE account_registration_verification_intents_159",
		"DROP TABLE account_registration_terms_159", "DROP TABLE account_registration_requests_159",
		"DROP INDEX users_phone_registration_unique_159", "DROP INDEX users_email_registration_unique_159",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("159 down missing %q", required)
		}
	}
	if refusal, drop := strings.Index(down, "migration 159 rollback would discard account registration facts"),
		strings.Index(down, "DROP TABLE account_registration_verification_intents_159"); refusal < 0 || drop < 0 || refusal > drop {
		t.Fatal("159 fact refusal must precede destructive rollback")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("159 migration contains forbidden marker %q", forbidden)
		}
	}
}
