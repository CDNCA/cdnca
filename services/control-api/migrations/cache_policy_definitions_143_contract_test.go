package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestCachePolicyDefinitions143Contract(t *testing.T) {
	up := readCachePolicyDefinitions143(t, "143_cache_policy_definitions.up.sql")
	down := readCachePolicyDefinitions143(t, "143_cache_policy_definitions.down.sql")
	for _, required := range []string{
		"migration 143 requires the exact verified 142 release head",
		"version = 142 AND migration_id = '142_cache_policy_schema_v2'",
		"checksum_sha256 = '49efd140a0340330159d97baa9573b2a82992a76a5a596e19450bf1bb2fc5e25'",
		"down_checksum_sha256 = '36fd6ac4f28a4381d3b66ede33d81c2abbb01661cdeabae6fdd39341d5b9e52c'",
		"CREATE TABLE cache_policy_definition_heads",
		"CREATE TABLE cache_policy_definition_revisions",
		"ADD COLUMN binding_mode text",
		"ADD COLUMN definition_id uuid",
		"ADD COLUMN definition_revision bigint",
		"CHECK (binding_mode IN ('inherit','override'))",
		"FOREIGN KEY (scope_id,definition_id,definition_revision)",
		"REFERENCES cache_policy_definition_revisions(scope_id,definition_id,revision)",
		"CREATE FUNCTION validate_cache_policy_binding_143()",
		"cache policy binding document does not match definition revision",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("143 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 143 requires the exact verified 142 release head"), strings.Index(up, "CREATE TABLE cache_policy_definition_heads"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("143 predecessor guard must run before the first mutation")
	}
	for _, required := range []string{
		"migration 143 rollback requires the exact verified 143 head",
		"checksum_sha256 = 'bbe9d4210c9cd5d58a831e210a5a57586723824d25c1deb70cabcdf5efbd8147'",
		"migration 143 rollback would discard reusable cache policy bindings",
		"DROP COLUMN definition_revision",
		"DROP TABLE cache_policy_definition_revisions",
		"DROP TABLE cache_policy_definition_heads",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("143 down missing %q", required)
		}
	}
}

func readCachePolicyDefinitions143(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
