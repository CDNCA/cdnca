package migrations

import (
	"strings"
	"testing"
)

// Migration 653: Turnstile / reCAPTCHA v3
// providers, the score threshold and unavailable columns and the console
// credential table. NULL columns keep the revision document without the keys;
// state transitions may not change them. Down restores 646's function verbatim
// and refuses while any revision or credential carries the new facts.
func TestChallengeExternalCaptcha653Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("653_challenge_external_captcha.up.sql"), read("653_challenge_external_captcha.down.sql")
	for _, fragment := range []string{
		"ERRCODE='P6530'", "(SELECT count(*) FROM schema_migrations) <> 652",
		"external_provider IN ('tencent', 'geetest-v4', 'turnstile', 'recaptcha-v3')",
		"ADD COLUMN external_score_threshold numeric(2,1)", "ADD COLUMN external_unavailable text",
		"external_score_threshold BETWEEN 0.1 AND 0.9 AND external_provider = 'recaptcha-v3'",
		"external_unavailable IN ('builtin', 'closed') AND mode = 'external'",
		"jsonb_build_object('score_threshold', NEW.external_score_threshold)",
		"jsonb_build_object('unavailable', NEW.external_unavailable)",
		"NEW.external_score_threshold IS DISTINCT FROM previous.external_score_threshold",
		"NEW.external_unavailable IS DISTINCT FROM previous.external_unavailable",
		"NEW.pow_difficulty IS DISTINCT FROM previous.pow_difficulty",
		"CREATE TABLE challenge_external_credentials",
		"REFERENCES challenge_policies(tenant_scope_id, id) ON DELETE RESTRICT",
		"REVOKE ALL ON challenge_external_credentials FROM PUBLIC",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("653 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"ERRCODE='P6531'", "ERRCODE='P6552'", "migration_id='653_challenge_external_captcha'",
		"DROP TABLE challenge_external_credentials", "DROP COLUMN external_score_threshold",
		"external_provider IN ('tencent', 'geetest-v4')",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("653 down missing %q", fragment)
		}
	}
	previous := read("646_challenge_pow_difficulty.up.sql")
	start := strings.Index(previous, "CREATE OR REPLACE FUNCTION validate_challenge_policy_revision_053()")
	end := strings.Index(previous[start:], "\n$$;\n")
	if start < 0 || end < 0 {
		t.Fatal("646 validate function not found")
	}
	if !strings.Contains(down, previous[start:start+end]) {
		t.Error("653 down does not restore 646's validate_challenge_policy_revision_053 verbatim")
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE challenge", "INSERT INTO"} {
		if strings.Contains(up, forbidden) || strings.Contains(down, forbidden) {
			t.Errorf("653 must not contain %q", forbidden)
		}
	}
}
