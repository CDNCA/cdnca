package migrations

import (
	"strings"
	"testing"
)

// Migration 683: identity_login_captchas gains the keyed
// digest of the browser binding cookie on the exact verified 682 head; rows
// issued before it keep NULL (spent as invalid); down drops it again.
func TestLoginCaptchaBinding683Contract(t *testing.T) {
	up, err := FS.ReadFile("683_login_captcha_binding.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("683_login_captcha_binding.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, identity_login_captchas IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 682", "(SELECT max(version) FROM schema_migrations) <> 682",
		"migration_id='682_registration_username_required'", "column_name='binding_digest'", "ERRCODE='P6830'",
		"ADD COLUMN binding_digest bytea,",
		"binding_digest IS NULL OR octet_length(binding_digest) = 32",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("683 up missing %q", fragment)
		}
	}
	if strings.Contains(string(up), "DELETE") || strings.Contains(string(up), "UPDATE") {
		t.Error("683 up must not rewrite issued CAPTCHAs")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 683", "migration_id='683_login_captcha_binding'", "ERRCODE='P6831'",
		"DROP CONSTRAINT identity_login_captchas_binding_683_check", "DROP COLUMN binding_digest",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("683 down missing %q", fragment)
		}
	}
}
