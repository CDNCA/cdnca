//go:build integration

package migrations_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestBillingBridgeKeys556: up/down/up; a reseller key needs an active
// reseller, owner kind matches the scope, keys are not deleted and revocation
// is final; the platform owner holds billing_bridge.manage.
func TestBillingBridgeKeys556(t *testing.T) {
	const version = 556
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}
	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	at := time.Now().UTC()
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY created_at LIMIT 1`).Scan(&platform); err != nil {
		platform = uuid.New()
		if err := exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform); err != nil {
			t.Fatal(err)
		}
	}
	user, tenant, scope := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash,status) VALUES($1,$2,'bb','unused','active')`, []any{user, "bb-" + user.String()[:8]}},
		{`INSERT INTO tenants(id,display_name,status) VALUES($1,'bb tenant','active')`, []any{tenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scope, tenant}},
	} {
		if err := exec(statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(owner uuid.UUID, kind, keyID string) error {
		return exec(`INSERT INTO billing_bridge_keys(id,owner_scope_id,owner_kind,name,key_id,secret_seed,pepper_version,
			ip_allowlist,status,created_by,revision,created_at,updated_at)
			VALUES($1,$2,$3,'whmcs',$4,$5,'v1',ARRAY['203.0.113.0/24']::cidr[],'active',$6,1,$7,$7)`,
			uuid.New(), owner, kind, keyID, bytes.Repeat([]byte{1}, 32), user, at)
	}
	if err := insert(scope, "reseller", "cbb_RRRRRRRRRRRRRRRRRRRRRR"); code(err) != "P5564" {
		t.Fatalf("non-reseller key err=%v", err)
	}
	if err := insert(scope, "platform", "cbb_RRRRRRRRRRRRRRRRRRRRRR"); code(err) != "P5563" {
		t.Fatalf("tenant scope as platform err=%v", err)
	}
	if err := exec(`INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,updated_by_user_id,
		updated_at) VALUES($1,'active',1,$2,$3,$2,$3)`, scope, user, at); err != nil {
		t.Fatal(err)
	}
	if err := insert(scope, "reseller", "cbb_RRRRRRRRRRRRRRRRRRRRRR"); err != nil {
		t.Fatalf("active reseller key: %v", err)
	}
	if err := insert(platform, "platform", "cbb_PPPPPPPPPPPPPPPPPPPPPP"); err != nil {
		t.Fatalf("platform key: %v", err)
	}
	if err := exec(`INSERT INTO billing_bridge_keys(id,owner_scope_id,owner_kind,name,key_id,secret_seed,pepper_version,
		ip_allowlist,status,created_by,revision,created_at,updated_at)
		VALUES($1,$2,'platform','x','cbb_EEEEEEEEEEEEEEEEEEEEEE',$3,'v1',ARRAY[]::cidr[],'active',$4,1,$5,$5)`,
		uuid.New(), platform, bytes.Repeat([]byte{1}, 32), user, at); code(err) != "23514" {
		t.Fatalf("empty allowlist err=%v", err)
	}
	if err := exec(`DELETE FROM billing_bridge_keys WHERE key_id='cbb_PPPPPPPPPPPPPPPPPPPPPP'`); code(err) != "P5561" {
		t.Fatalf("delete err=%v", err)
	}
	// Suspending the reseller blocks a new secret but not revocation.
	if err := exec(`UPDATE reseller_profiles SET status='suspended', suspended_at=$2, revision=revision+1 WHERE scope_id=$1`,
		scope, at); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE billing_bridge_keys SET secret_seed=$1, revision=revision+1 WHERE key_id='cbb_RRRRRRRRRRRRRRRRRRRRRR'`,
		bytes.Repeat([]byte{2}, 32)); code(err) != "P5564" {
		t.Fatalf("rotate for suspended reseller err=%v", err)
	}
	if err := exec(`UPDATE billing_bridge_keys SET status='revoked', revoked_at=$1, revision=revision+1
		WHERE key_id='cbb_RRRRRRRRRRRRRRRRRRRRRR'`, at); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := exec(`UPDATE billing_bridge_keys SET status='active', revoked_at=NULL WHERE key_id='cbb_RRRRRRRRRRRRRRRRRRRRRR'`); code(err) != "P5562" {
		t.Fatalf("unrevoke err=%v", err)
	}
	if err := exec(`INSERT INTO billing_bridge_nonces(key_id,nonce,seen_at) VALUES('cbb_PPPPPPPPPPPPPPPPPPPPPP','nonce-0123456789ab',$1)`, at); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO billing_bridge_nonces(key_id,nonce,seen_at) VALUES('cbb_PPPPPPPPPPPPPPPPPPPPPP','nonce-0123456789ab',$1)`, at); code(err) != "23505" {
		t.Fatalf("nonce reuse err=%v", err)
	}
	var held bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_permissions rp JOIN roles r ON r.id=rp.role_id
		JOIN access_scopes s ON s.id=r.scope_id AND s.kind='platform'
		WHERE r.system_role AND r.name='platform_owner' AND rp.permission_name='billing_bridge.manage')`).Scan(&held); err != nil {
		t.Fatal(err)
	}
	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles r JOIN access_scopes s ON s.id=r.scope_id AND s.kind='platform'
		WHERE r.system_role AND r.name='platform_owner'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners > 0 && !held {
		t.Fatal("platform_owner lacks billing_bridge.manage")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("down with keys present must be refused (P5566)")
	}
}
