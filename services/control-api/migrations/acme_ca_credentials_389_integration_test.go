//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestACMECACredentials389: one credential row per EAB CA on the platform
// scope only; the system configuration accepts google_trust as the issuer;
// up, down and up again.
func TestACMECACredentials389(t *testing.T) {
	const version = 389
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	platform, tenantScope, tenant, user := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'389 tenant')`, tenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'eab-389','EAB','unused')`, user)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$2)`, platform, user, tenantScope)
	insert := `INSERT INTO acme_ca_credentials(platform_scope_id,ca,directory_url,eab_key_id,eab_hmac_key_id,
		eab_hmac_ciphertext,eab_hmac_sha256_prefix,revision,updated_by_user_id,updated_at)
		VALUES($1,$2,'https://acme.zerossl.com/v2/DV90','kid-1','dns-key',$3,'0123abcd',1,$4,now())`
	mustExec(t, pool, insert, platform, "zerossl", []byte("0123456789abcdef0123"), user)
	if _, err := pool.Exec(ctx, insert, platform, "zerossl", []byte("0123456789abcdef0123"), user); sqlState(err) != "23505" {
		t.Fatalf("second zerossl row: %v, want 23505", err)
	}
	if _, err := pool.Exec(ctx, insert, platform, "lets_encrypt", []byte("0123456789abcdef0123"), user); sqlState(err) != "23514" {
		t.Fatalf("unknown CA: %v, want 23514", err)
	}
	if _, err := pool.Exec(ctx, insert, tenantScope, "google_trust", []byte("0123456789abcdef0123"), user); sqlState(err) != "P3891" {
		t.Fatalf("tenant scope row: %v, want P3891", err)
	}
	var accepts bool
	if err := pool.QueryRow(ctx, `SELECT system_configuration_v2_defaults_override('{"certificate":{"issuer":"google_trust"}}'::jsonb, '{}'::jsonb)`).
		Scan(&accepts); err != nil || !accepts {
		t.Fatalf("google_trust override accepted=%v (%v)", accepts, err)
	}
}
