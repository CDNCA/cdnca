package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestBILL07PackagePeriodResetWorkloadAuthority165Contract(t *testing.T) {
	predecessorUp := mustReadMigration165(t, "164_package_period_reset.up.sql")
	predecessorDown := mustReadMigration165(t, "164_package_period_reset.down.sql")
	upBytes := mustReadMigration165(t, "165_package_period_reset_workload_authority.up.sql")
	downBytes := mustReadMigration165(t, "165_package_period_reset_workload_authority.down.sql")
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 165 requires the exact verified 164 release head",
		"version=164 AND migration_id='164_package_period_reset'",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)), fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"CREATE TABLE package_period_reset_workload_authority_bindings_165",
		"audience text NOT NULL CHECK(audience='package_period_reset')",
		"permission_name text NOT NULL CHECK(permission_name='sites.manage')",
		"FOREIGN KEY(tenant_scope_id,actor_user_id)", "REFERENCES memberships(scope_id,user_id)",
		"CREATE UNIQUE INDEX package_period_reset_workload_authority_active_tenant_165",
		"WHERE revoked_at IS NULL", "NEW.revision<>OLD.revision+1", "only permits one-way revocation",
		"cannot be deleted", "cannot be truncated", "REVOKE ALL ON package_period_reset_workload_authority_bindings_165",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("165 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 165 requires the exact verified 164 release head"),
		strings.Index(up, "CREATE TABLE package_period_reset_workload_authority_bindings_165");
		guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("165 predecessor guard must precede the first schema mutation")
	}
	for _, forbidden := range []string{"CASCADE", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("165 migration contains forbidden marker %q", forbidden)
		}
	}
	for _, required := range []string{
		"migration 165 rollback requires the exact verified 165 head",
		"version=165 AND migration_id='165_package_period_reset_workload_authority'",
		fmt.Sprintf("%x", sha256.Sum256(upBytes)),
		"migration 165 rollback would discard package period reset workload authority facts",
		"DROP TABLE package_period_reset_workload_authority_bindings_165",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("165 down missing %q", required)
		}
	}
}

func mustReadMigration165(t *testing.T, name string) []byte {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
