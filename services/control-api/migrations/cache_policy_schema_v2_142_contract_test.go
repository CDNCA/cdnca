package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestCachePolicySchemaV2142Contract(t *testing.T) {
	up := readCachePolicySchemaV2142(t, "142_cache_policy_schema_v2.up.sql")
	down := readCachePolicySchemaV2142(t, "142_cache_policy_schema_v2.down.sql")
	for _, required := range []string{
		"migration 142 requires the exact verified 141 release head",
		"version = 141 AND migration_id = '141_platform_global_announcements'",
		"checksum_sha256 = 'd078248a163d03698eb559bec8c45b5f7ebc6b682603ed6e1f6448958c26af7f'",
		"down_checksum_sha256 = '5d7a9b8201d9bd9b425284aa8bc6a96e54180c23bc233a913e44f2a5ac241da5'",
		"ADD COLUMN schema_version smallint NOT NULL DEFAULT 1",
		"CHECK (schema_version IN (1,2))",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("142 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 142 requires the exact verified 141 release head"), strings.Index(up, "ALTER TABLE cache_policy_revisions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("142 predecessor guard must run before the first mutation")
	}
	for _, required := range []string{
		"migration 142 rollback requires the exact verified 142 head",
		"version = 142 AND migration_id = '142_cache_policy_schema_v2'",
		"checksum_sha256 = '49efd140a0340330159d97baa9573b2a82992a76a5a596e19450bf1bb2fc5e25'",
		"version = 141 AND migration_id = '141_platform_global_announcements'",
		"migration 142 rollback would discard cache policy V2 facts",
		"WHERE schema_version = 2",
		"DROP COLUMN schema_version",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("142 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 142 rollback requires the exact verified 142 head"), strings.Index(down, "DROP CONSTRAINT"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("142 rollback guard must run before the first mutation")
	}
}

func readCachePolicySchemaV2142(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
