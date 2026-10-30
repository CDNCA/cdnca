package migrations

import (
	"strings"
	"testing"
)

func TestCCReferences205Contract(t *testing.T) {
	up, err := FS.ReadFile("205_cc_references.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("205_cc_references.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration_205", "204_platform_brand_assets_permissions",
		"CREATE TABLE cc_reference_matchers", "CREATE TABLE cc_reference_filters",
		"CREATE TABLE cc_reference_versions", "CREATE TABLE cc_reference_write_requests",
		"security_policies", "GRANT SELECT,INSERT,UPDATE,DELETE",
		"gen_random_uuid()", "jsonb_array_elements",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("migration 205 missing %q", required)
		}
	}
	for _, required := range []string{
		"DROP TABLE cc_reference_write_requests", "DROP TABLE cc_reference_versions",
		"DROP TABLE cc_reference_filters", "DROP TABLE cc_reference_matchers",
		"REVOKE SELECT,INSERT,UPDATE,DELETE",
	} {
		if !strings.Contains(string(down), required) {
			t.Fatalf("migration 205 down missing %q", required)
		}
	}
}
