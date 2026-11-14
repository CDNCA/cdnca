//go:build integration

package migrations_test

import "testing"

// 667: 666 -> 667 -> 666 -> 667. The three SMTP password columns and their pairing check come and
// go; down refuses (P6672) while a page-saved password is stored.
func TestSystemMailSMTPPassword667UpDownUp(t *testing.T) {
	const version = 667
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	columns := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='platform_system_mail_settings' AND
			column_name IN ('smtp_password_key_id','smtp_password_ciphertext','smtp_password_fingerprint')`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if got := columns(); got != 0 {
		t.Fatalf("before 667: %d columns", got)
	}
	for _, step := range []struct {
		direction string
		want      int
	}{{"up", 3}, {"down", 0}, {"up", 3}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := columns(); got != step.want {
			t.Fatalf("after %s: got %d columns want %d", step.direction, got, step.want)
		}
	}
	const platform = "66700000-0000-4000-8000-000000000001"
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO platform_system_mail_settings
		(platform_scope_id,revision,settings,updated_at,smtp_password_key_id,smtp_password_ciphertext,smtp_password_fingerprint)
		VALUES($1,1,'{}',now(),'k1',decode(repeat('00',29),'hex'),'0123456789abcdef')`, platform); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("667 down dropped a saved SMTP password")
	}
}
