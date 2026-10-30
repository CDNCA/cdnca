package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestIAMManagedPasswordReset166Contract(t *testing.T) {
	predecessorUp := mustReadManagedPasswordResetMigration(t, "165_package_period_reset_workload_authority.up.sql")
	predecessorDown := mustReadManagedPasswordResetMigration(t, "165_package_period_reset_workload_authority.down.sql")
	upBytes := mustReadManagedPasswordResetMigration(t, "166_identity_managed_password_reset.up.sql")
	downBytes := mustReadManagedPasswordResetMigration(t, "166_identity_managed_password_reset.down.sql")
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 166 requires the exact verified 165 release head",
		"version=165 AND migration_id='165_package_period_reset_workload_authority'",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"LOCK TABLE schema_migrations,identity_write_requests IN ACCESS EXCLUSIVE MODE",
		"'identity.user.password.reset'",
		"identity_write_requests_secret_hash_check",
		"operation IN ('identity.user.create','identity.user.password.reset') AND secret_hash IS NOT NULL",
		"operation NOT IN ('identity.user.create','identity.user.password.reset') AND secret_hash IS NULL",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("166 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 166 requires the exact verified 165 release head"),
		strings.Index(up, "ALTER TABLE identity_write_requests"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("166 predecessor guard must precede the first schema mutation")
	}
	for _, forbidden := range []string{"CASCADE", "DROP SCHEMA", "__UP_SHA256__", "password text", "step_up_token"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("166 migration contains forbidden marker %q", forbidden)
		}
	}
	for _, required := range []string{
		"migration 166 rollback requires the exact verified 166 head",
		"version=166 AND migration_id='166_identity_managed_password_reset'",
		fmt.Sprintf("%x", sha256.Sum256(upBytes)),
		"migration 166 rollback would discard managed password reset receipts",
		"operation='identity.user.password.reset'",
		"identity_write_requests_operation_check",
		"identity_write_requests_check",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("166 down missing %q", required)
		}
	}
}

func mustReadManagedPasswordResetMigration(t *testing.T, name string) []byte {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
