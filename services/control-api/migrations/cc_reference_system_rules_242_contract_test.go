package migrations

import (
	"strings"
	"testing"
)

func TestCCReferenceSystemRules242Contract(t *testing.T) {
	up, err := FS.ReadFile("242_cc_reference_system_rules.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("242_cc_reference_system_rules.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration_242_up",
		"system_rule_id", "system_rule_sort", "system_rule_key",
		"cc_reference_matchers_scope_name_kind_active_idx",
		"cc_reference_filters_scope_name_kind_active_idx",
		"cc_reference_matchers_scope_system_key_active_idx",
		"cc_reference_filters_scope_system_key_active_idx",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration 242 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"ON cc_reference_matchers(scope_id,system_rule_key)",
		"ON cc_reference_filters(scope_id,system_rule_key)",
		"WHERE deleted_at IS NULL AND system_rule AND system_rule_key <> ''",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("migration 242 is missing logical system-rule uniqueness %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(string(up)+string(down)), "CASCADE") {
		t.Fatal("migration 242 must not use CASCADE")
	}
}
