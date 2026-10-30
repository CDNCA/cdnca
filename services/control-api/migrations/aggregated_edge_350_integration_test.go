//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAggregatedEdge350 rolls 350 up, down and up, then checks the account
// credential fence (every credential change or disable bumps the version;
// a revoked credential cannot be re-enabled without a new one), the supply
// mode constraints, and that down refuses once an account exists.
func TestAggregatedEdge350(t *testing.T) {
	const version = 350
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM permissions WHERE name='edge.aggregated.manage')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("permission seeded = %v, %v", granted, err)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM aggregated_edge_runtime`).Scan(&state); err != nil || state != "inactive" {
		t.Fatalf("runtime state = %q, %v", state, err)
	}

	platform, user, account := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ae-350','AE 350','unused')`, user)
	mustExec(t, pool, `INSERT INTO cdn_provider_accounts(id,platform_scope_id,provider,name,credential_key_id,
		credential_ciphertext,hostname_limit,created_by,updated_by,created_at,updated_at)
		VALUES($1,$2,'cloudflare','cf',$3,$4,100,$5,$5,$6,$6)`, account, platform, "key-a", make([]byte, 64), user, now)

	readFence := func() (int64, bool) {
		t.Helper()
		var version int64
		var revoked bool
		if err := pool.QueryRow(ctx, `SELECT credential_version,credential_revoked FROM cdn_provider_accounts WHERE id=$1`,
			account).Scan(&version, &revoked); err != nil {
			t.Fatal(err)
		}
		return version, revoked
	}
	mustExec(t, pool, `UPDATE cdn_provider_accounts SET name='renamed' WHERE id=$1`, account)
	if version, revoked := readFence(); version != 1 || revoked {
		t.Fatalf("rename moved the fence: %d %v", version, revoked)
	}
	ciphertext := make([]byte, 64)
	ciphertext[0] = 1
	mustExec(t, pool, `UPDATE cdn_provider_accounts SET credential_ciphertext=$2 WHERE id=$1`, account, ciphertext)
	if version, revoked := readFence(); version != 2 || revoked {
		t.Fatalf("rotation fence = %d %v, want 2 false", version, revoked)
	}
	mustExec(t, pool, `UPDATE cdn_provider_accounts SET credential_version=99, credential_revoked=true WHERE id=$1`, account)
	if version, revoked := readFence(); version != 2 || revoked {
		t.Fatalf("direct fence write accepted: %d %v", version, revoked)
	}
	mustExec(t, pool, `UPDATE cdn_provider_accounts SET status='disabled' WHERE id=$1`, account)
	if version, revoked := readFence(); version != 3 || !revoked {
		t.Fatalf("disable fence = %d %v, want 3 true", version, revoked)
	}
	if _, err := pool.Exec(ctx, `UPDATE cdn_provider_accounts SET status='verified' WHERE id=$1`, account); sqlState(err) != "P3502" {
		t.Fatalf("re-enable without new credential: %v, want P3502", err)
	}
	ciphertext[0] = 2
	mustExec(t, pool, `UPDATE cdn_provider_accounts SET status='unverified', credential_ciphertext=$2 WHERE id=$1`, account, ciphertext)
	if version, revoked := readFence(); version != 4 || revoked {
		t.Fatalf("re-enable with new credential = %d %v, want 4 false", version, revoked)
	}

	supply := uuid.New()
	mustExec(t, pool, `INSERT INTO site_supplies(id,platform_scope_id,kind,name,created_at,updated_at)
		VALUES($1,$2,'third_party_cdn','cf supply',$3,$3)`, supply, platform, now)
	if _, err := pool.Exec(ctx, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,created_at,updated_at)
		VALUES($1,'cloudflare','config_sync',$2,$2)`, supply, now); sqlState(err) != "23514" {
		t.Fatalf("config_sync without account: %v, want check violation", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,account_id,created_at,updated_at)
		VALUES($1,'edgeone','config_sync',$2,$3,$3)`, supply, account, now); sqlState(err) != "23503" {
		t.Fatalf("account of another provider: %v, want foreign key violation", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,created_at,updated_at)
		VALUES($1,'cloudflare','schedule_only',$2,$2)`, supply, now); sqlState(err) != "23514" {
		t.Fatalf("schedule_only without endpoint: %v, want check violation", err)
	}
	mustExec(t, pool, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,account_id,created_at,updated_at)
		VALUES($1,'cloudflare','config_sync',$2,$3,$3)`, supply, account, now)

	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3503" {
		t.Fatalf("down with accounts: %v, want P3503", err)
	}
}
