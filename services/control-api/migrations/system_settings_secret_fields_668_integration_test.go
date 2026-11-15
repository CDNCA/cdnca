//go:build integration

package migrations_test

import "testing"

// 668: 667 -> 668 -> 667 -> 668. The user settings secrets envelope and the SMS gateway token
// columns come and go; down refuses (P6682) while either holds a page-saved secret.
func TestSystemSettingsSecretFields668UpDownUp(t *testing.T) {
	const version = 668
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	columns := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND (
			    table_name='platform_system_user_settings' AND column_name IN ('secrets_key_id','secrets_ciphertext','secrets_fingerprints') OR
			    table_name='platform_system_mail_settings' AND
			    column_name IN ('sms_auth_token_key_id','sms_auth_token_ciphertext','sms_auth_token_fingerprint'))`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if got := columns(); got != 0 {
		t.Fatalf("before 668: %d columns", got)
	}
	for _, step := range []struct {
		direction string
		want      int
	}{{"up", 6}, {"down", 0}, {"up", 6}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := columns(); got != step.want {
			t.Fatalf("after %s: got %d columns want %d", step.direction, got, step.want)
		}
	}
	const platform = "66800000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	// fingerprints may only name the six page secrets
	if _, err := pool.Exec(ctx, `INSERT INTO platform_system_user_settings
		(platform_scope_id,revision,settings,updated_at,secrets_key_id,secrets_ciphertext,secrets_fingerprints)
		VALUES($1,1,'{}',now(),'k1',decode(repeat('00',29),'hex'),'{"smtp_password":"0123456689abcdef"}')`, platform); err == nil {
		t.Fatal("668 accepted an unknown secret fingerprint")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO platform_system_user_settings
		(platform_scope_id,revision,settings,updated_at,secrets_key_id,secrets_ciphertext,secrets_fingerprints)
		VALUES($1,1,'{}',now(),'k1',decode(repeat('00',29),'hex'),'{"captcha_app_secret":"0123456689abcdef","captcha_turnstile_secret":"0123456689abcdef"}')`, platform); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("668 down dropped saved user settings secrets")
	}
	if _, err := pool.Exec(ctx, `UPDATE platform_system_user_settings SET secrets_key_id=NULL,secrets_ciphertext=NULL,secrets_fingerprints=NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO platform_system_mail_settings
		(platform_scope_id,revision,settings,updated_at,sms_auth_token_key_id,sms_auth_token_ciphertext,sms_auth_token_fingerprint)
		VALUES($1,1,'{}',now(),'k1',decode(repeat('00',29),'hex'),'0123456689abcdef')`, platform); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("668 down dropped a saved SMS gateway token")
	}
}
