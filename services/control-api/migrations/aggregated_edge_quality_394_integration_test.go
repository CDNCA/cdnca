//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAggregatedEdgeQuality394 rolls 394 up, down and up, then checks: the
// strategy defaults to failover and rejects unknown values; probe rounds
// follow their health row; a quality switch is accepted; down refuses while
// quality switch history exists.
func TestAggregatedEdgeQuality394(t *testing.T) {
	const version = 394
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
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ae-394','AE 394','unused')`, user)
	supply := uuid.New()
	mustExec(t, pool, `INSERT INTO site_supplies(id,platform_scope_id,kind,name,target,created_at,updated_at)
		VALUES($1,$2,'third_party_cdn','cf 394','cf.quality-394.test',$3,$3)`, supply, platform, now)
	tenant, scope, owner, site := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'394 tenant')`, tenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'site-394','Site 394','unused')`, owner)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, owner)
	seedSite362(ctx, t, pool, scope, owner, site, 1, "www.quality-394.test")

	mustExec(t, pool, `INSERT INTO aggregated_edge_site_schedules(site_id,updated_at) VALUES($1,$2)`, site, now)
	var strategy string
	var interval int
	var margin float64
	if err := pool.QueryRow(ctx, `SELECT strategy,quality_min_interval_seconds,quality_margin::float8
		FROM aggregated_edge_site_schedules WHERE site_id=$1`, site).Scan(&strategy, &interval, &margin); err != nil ||
		strategy != "failover" || interval != 600 || margin != 0.3 {
		t.Fatalf("defaults = %q %d %v, %v", strategy, interval, margin, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE aggregated_edge_site_schedules SET strategy='fastest' WHERE site_id=$1`, site); sqlState(err) != "23514" {
		t.Fatalf("unknown strategy: %v, want check violation", err)
	}
	mustExec(t, pool, `UPDATE aggregated_edge_site_schedules SET strategy='quality' WHERE site_id=$1`, site)

	mustExec(t, pool, `INSERT INTO aggregated_edge_target_health(site_id,supply_id,line_scope,next_round_at,updated_at)
		VALUES($1,$2,'overseas',$3,$3)`, site, supply, now)
	mustExec(t, pool, `INSERT INTO aggregated_edge_probe_rounds(site_id,supply_id,line_scope,round_at,healthy,latency_ms,ok,failed)
		VALUES($1,$2,'overseas',$3,true,42,3,0)`, site, supply, now)
	if _, err := pool.Exec(ctx, `INSERT INTO aggregated_edge_probe_rounds(site_id,supply_id,line_scope,round_at,healthy,ok,failed)
		VALUES($1,$2,'telecom',$3,true,2,0)`, site, supply, now); sqlState(err) != "23503" {
		t.Fatalf("round without a health row: %v, want foreign key violation", err)
	}
	mustExec(t, pool, `DELETE FROM aggregated_edge_target_health WHERE site_id=$1`, site)
	var rounds int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM aggregated_edge_probe_rounds WHERE site_id=$1`, site).Scan(&rounds); err != nil ||
		rounds != 0 {
		t.Fatalf("rounds after the health row went = %d, %v", rounds, err)
	}

	mustExec(t, pool, `INSERT INTO aggregated_edge_switch_events(id,site_id,line_scope,reason,created_at)
		VALUES($1,$2,'overseas','quality',$3)`, uuid.New(), site, now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3942" {
		t.Fatalf("down with quality switch history: %v, want P3942", err)
	}
}
