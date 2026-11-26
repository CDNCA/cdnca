//go:build integration

package migrations_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

// TestLoginCaptchaBinding683: a CAPTCHA issued at 682
// keeps its row with a NULL binding_digest after 683 (identity spends it as
// invalid); only a 32-byte digest is accepted; down drops the column and
// leaves the rows.
func TestLoginCaptchaBinding683(t *testing.T) {
	const version = 683
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	legacy := uuid.New()
	mustExec(t, pool, `INSERT INTO identity_login_captchas(id,answer_digest,source_ip,created_at,expires_at)
		VALUES($1,$2,'104.23.1.10',now(),now()+interval '5 minutes')`, legacy, bytes.Repeat([]byte{1}, 32))
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var unbound bool
	if err := pool.QueryRow(ctx, `SELECT binding_digest IS NULL FROM identity_login_captchas WHERE id=$1`, legacy).Scan(&unbound); err != nil || !unbound {
		t.Fatalf("legacy row after 683: unbound=%v err=%v", unbound, err)
	}
	mustExec(t, pool, `INSERT INTO identity_login_captchas(id,answer_digest,binding_digest,source_ip,created_at,expires_at)
		VALUES($1,$2,$3,'104.23.1.10',now(),now()+interval '5 minutes')`, uuid.New(), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if _, err := pool.Exec(ctx, `INSERT INTO identity_login_captchas(id,answer_digest,binding_digest,source_ip,created_at,expires_at)
		VALUES($1,$2,$3,'104.23.1.10',now(),now()+interval '5 minutes')`, uuid.New(), bytes.Repeat([]byte{1}, 32), []byte("plain")); err == nil {
		t.Fatal("a binding that is not a 32-byte digest was accepted")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	var rows, columns int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_login_captchas),
		(SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND
			table_name='identity_login_captchas' AND column_name='binding_digest')`).Scan(&rows, &columns); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || columns != 0 {
		t.Fatalf("after down: rows=%d binding columns=%d", rows, columns)
	}
}
