package migrations

import (
	"strings"
	"testing"
)

// Migration 695: on the exact
// verified 694 head, validate_security_policy_publication_insert lets a
// claim name the binding's last claimed version of the same library again
// only when that claim's candidate failed, was cancelled or expired and has
// recovered. Everything else is 470's text; down restores 470.
func TestSecurityPublicationReclaim695Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("695_security_publication_reclaim.up.sql"), read("695_security_publication_reclaim.down.sql")
	m470 := read("470_security_binding_rebind.up.sql")
	start := strings.Index(m470, "CREATE OR REPLACE FUNCTION validate_security_policy_publication_insert()")
	end := strings.Index(m470[start:], "$$;\n")
	if start < 0 || end < 0 {
		t.Fatal("470 publication guard not found")
	}
	original := m470[start : start+end+4]
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 694", "(SELECT max(version) FROM schema_migrations) <> 694",
		"migration_id='694_package_change_current_entitlement_lines'", "ERRCODE='P6950'",
		"NEW.policy_version = binding.last_claimed_policy_version AND",
		"candidate.last_bundle_id = binding.last_bundle_id",
		"candidate.candidate_status IN ('failed','cancelled','expired')",
		"candidate.recovered_at IS NOT NULL",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("695 up missing %q", fragment)
		}
	}
	reclaim := strings.Index(up, " AND NOT (\n")
	closing := strings.Index(up, "\n                )))\n")
	if reclaim < 0 || closing < 0 {
		t.Fatal("695 reclaim clause not found")
	}
	if got := up[strings.Index(up, "CREATE OR REPLACE FUNCTION"):reclaim] + ")\n" + up[closing+len("\n                )))\n"):]; got != original {
		t.Errorf("695 up changes the 470 guard beyond the reclaim clause:\n%s", got)
	}
	if !strings.Contains(down, "ERRCODE='P6951'") || !strings.HasSuffix(down, original) {
		t.Error("695 down does not restore the 470 guard")
	}
}
