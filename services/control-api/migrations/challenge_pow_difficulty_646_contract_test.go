package migrations

import (
	"strings"
	"testing"
)

// Migration 646 (predecessor 645_plugin_local_disables_no_reason): an
// optional browser proof-of-work difficulty per challenge policy revision.
// NULL means the engine default and keeps the revision document without the
// key, so stored revisions and the 053 document check are unchanged; state
// transitions may not change it. Down restores 053's function and refuses
// while any revision carries an explicit difficulty.
func TestChallengePoWDifficulty646Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("646_challenge_pow_difficulty.up.sql"), read("646_challenge_pow_difficulty.down.sql")
	for _, fragment := range []string{
		"ERRCODE='P6460'", "(SELECT count(*) FROM schema_migrations) <> 645",
		"migration_id='645_plugin_local_disables_no_reason'",
		"ADD COLUMN pow_difficulty integer",
		"pow_difficulty IS NULL OR (pow_difficulty BETWEEN 12 AND 24 AND mode <> 'external')",
		"CREATE OR REPLACE FUNCTION validate_challenge_policy_revision_053()",
		"IF NEW.pow_difficulty IS NOT NULL THEN\n        expected_document := expected_document || jsonb_build_object('pow_difficulty', NEW.pow_difficulty);",
		"NEW.pow_difficulty IS DISTINCT FROM previous.pow_difficulty",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("646 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"ERRCODE='P6461'", "ERRCODE='P6462'", "migration_id='646_challenge_pow_difficulty'",
		"WHERE pow_difficulty IS NOT NULL",
		"CREATE OR REPLACE FUNCTION validate_challenge_policy_revision_053()",
		"DROP COLUMN pow_difficulty",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("646 down missing %q", fragment)
		}
	}
	if strings.Contains(down, "pow_difficulty IS DISTINCT FROM") || strings.Contains(down, "'pow_difficulty', NEW") {
		t.Error("646 down must restore the 053 function without pow_difficulty")
	}
	// The restored function is 053's text exactly (only CREATE becomes CREATE OR REPLACE).
	original := read("053_challenge_policies.up.sql")
	start := strings.Index(original, "CREATE FUNCTION validate_challenge_policy_revision_053()")
	end := strings.Index(original[start:], "\n$$;\n")
	if start < 0 || end < 0 {
		t.Fatal("053 validate function not found")
	}
	restored := strings.Replace(original[start:start+end], "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
	if !strings.Contains(down, restored) {
		t.Error("646 down does not restore 053's validate_challenge_policy_revision_053 verbatim")
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE ", "DROP TABLE", "CREATE TABLE"} {
		if strings.Contains(up, forbidden) || strings.Contains(down, forbidden) {
			t.Errorf("646 must not contain %q", forbidden)
		}
	}
}
