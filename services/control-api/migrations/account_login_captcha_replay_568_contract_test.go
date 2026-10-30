package migrations

import (
	"strings"
	"testing"
)

// Migration 568 (fix-smallfu): local replay guard for Tencent / GeeTest v4
// login CAPTCHA tickets. Placeholder number; the 554 predecessor is pinned by
// checksum and is re-pinned to the actual head when merged.
func TestAccountLoginCaptchaReplay568Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"568_account_login_captcha_replay.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 567", "(SELECT max(version) FROM schema_migrations) <> 567",
			"migration_id='567_certificate_failure_reason'",
			"checksum_sha256='c56b6376f0fcbf45514391183d30991b2f58cdcf653aa15cfaf117dcedd0a2f7'",
			"down_checksum_sha256='57fc4a9409606e27bad433b61cd9388d69a0bc86ea39d9b3db3fc8c12eaacf3d'",
			"ERRCODE='P5680'", "CREATE TABLE account_login_captcha_replay_568",
			"token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32)",
			"provider IN ('tencent', 'geetest_v4')", "expires_at > used_at",
			"REVOKE ALL ON account_login_captcha_replay_568 FROM PUBLIC",
		}},
		{"568_account_login_captcha_replay.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 568", "migration_id='568_account_login_captcha_replay'",
			"ERRCODE='P5681'", "DROP TABLE account_login_captcha_replay_568",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
