//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAggregatedEdgeSync375 rolls 375 up, down and up, then checks: a site,
// origin or supply origin change bumps the sync row's source_generation (the
// incremental projection queue); waf_rule resources are accepted; down
// refuses while a published DNS record or a vendor WAF rule is recorded.
func TestAggregatedEdgeSync375(t *testing.T) {
	const version = 375
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	platform, user := uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ae-375','AE 375','unused')`, user)
	account := uuid.New()
	mustExec(t, pool, `INSERT INTO cdn_provider_accounts(id,platform_scope_id,provider,name,credential_key_id,
		credential_ciphertext,hostname_limit,created_by,updated_by,created_at,updated_at)
		VALUES($1,$2,'cloudflare','cf 375','key-a',$3,100,$4,$4,$5,$5)`, account, platform, make([]byte, 64), user, now)
	supply := uuid.New()
	mustExec(t, pool, `INSERT INTO site_supplies(id,platform_scope_id,kind,name,created_at,updated_at)
		VALUES($1,$2,'third_party_cdn','cf 375',$3,$3)`, supply, platform, now)
	mustExec(t, pool, `INSERT INTO site_supply_cdn_configs(supply_id,provider,mode,account_id,created_at,updated_at)
		VALUES($1,'cloudflare','config_sync',$2,$3,$3)`, supply, account, now)

	tenant, scope, owner, site := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'375 tenant')`, tenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'site-375','Site 375','unused')`, owner)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, owner)
	seedSite362(ctx, t, pool, scope, owner, site, 1, "www.sync-375.test")
	mustExec(t, pool, `INSERT INTO site_supply_cdn_sites(site_id,supply_id,next_observe_at,created_at,updated_at)
		VALUES($1,$2,$3,$3,$3)`, site, supply, now)

	generation := func() int64 {
		t.Helper()
		var value int64
		if err := pool.QueryRow(ctx, `SELECT source_generation FROM site_supply_cdn_sites WHERE site_id=$1`, site).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := generation()
	mustExec(t, pool, `UPDATE sites SET revision=revision+1 WHERE id=$1`, site)
	if generation() != before+1 {
		t.Fatalf("site change did not bump the queue: %d -> %d", before, generation())
	}
	mustExec(t, pool, `UPDATE sites SET updated_at=updated_at WHERE id=$1`, site)
	if generation() != before+1 {
		t.Fatal("an unrelated site column bumped the queue")
	}
	mustExec(t, pool, `UPDATE site_origins SET port=8443 WHERE site_id=$1`, site)
	mustExec(t, pool, `UPDATE site_supply_cdn_configs SET origin_server='origin.sync-375.test' WHERE supply_id=$1`, supply)
	mustExec(t, pool, `UPDATE cdn_provider_accounts SET fallback_origin='fallback.sync-375.test' WHERE id=$1`, account)
	if generation() != before+4 {
		t.Fatalf("origin/supply/fallback changes: generation %d, want %d", generation(), before+4)
	}

	mustExec(t, pool, `INSERT INTO site_supply_cdn_resources(site_id,supply_id,kind,name,remote_id,applied_fingerprint,updated_at)
		VALUES($1,$2,'waf_rule','waf','ruleset/rule',$3,$4)`, site, supply,
		"0000000000000000000000000000000000000000000000000000000000000000", now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3752" {
		t.Fatalf("down with a vendor WAF rule: %v, want P3752", err)
	}
	mustExec(t, pool, `DELETE FROM site_supply_cdn_resources WHERE kind='waf_rule'`)
	mustExec(t, pool, `INSERT INTO site_supply_cdn_validation_records(site_id,supply_id,purpose,record_name,record_value,
		state,dns_ref,next_attempt_at,created_at,updated_at)
		VALUES($1,$2,'certificate','_acme-challenge.www.sync-375.test','dcv-value','published','v2.handle',$3,$3,$3)`,
		site, supply, now)
	if _, err := pool.Exec(ctx, `INSERT INTO site_supply_cdn_validation_records(site_id,supply_id,purpose,record_name,record_value,
		state,next_attempt_at,created_at,updated_at)
		VALUES($1,$2,'ownership','_cf-custom-hostname.www.sync-375.test','own','published',$3,$3,$3)`, site, supply, now); sqlState(err) != "23514" {
		t.Fatalf("published without a dns reference: %v, want check violation", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3752" {
		t.Fatalf("down with a published DNS record: %v, want P3752", err)
	}
}
