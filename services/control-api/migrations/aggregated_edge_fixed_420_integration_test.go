//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestAggregatedEdgeFixed420 rolls 420 up, down and up, then checks: strategy
// fixed, the new alerts / switch reasons and the 保持 flags are
// accepted, unknown values still rejected, the notification event is seeded;
// down refuses while any of them is in use.
func TestAggregatedEdgeFixed420(t *testing.T) {
	const version = 420
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	platform := uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	supply := uuid.New()
	mustExec(t, pool, `INSERT INTO site_supplies(id,platform_scope_id,kind,name,target,created_at,updated_at)
		VALUES($1,$2,'third_party_cdn','cf 420','cf.fixed-420.test',$3,$3)`, supply, platform, now)
	tenant, scope, owner, site := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'420 tenant')`, tenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'site-420','Site 420','unused')`, owner)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, owner)
	seedSite362(ctx, t, pool, scope, owner, site, 1, "www.fixed-420.test")

	mustExec(t, pool, `INSERT INTO aggregated_edge_site_schedules(site_id,updated_at) VALUES($1,$2)`, site, now)
	if _, err := pool.Exec(ctx, `UPDATE aggregated_edge_site_schedules SET strategy='fastest' WHERE site_id=$1`, site); sqlState(err) != "23514" {
		t.Fatalf("unknown strategy: %v, want check violation", err)
	}
	mustExec(t, pool, `UPDATE aggregated_edge_site_schedules SET strategy='fixed' WHERE site_id=$1`, site)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4202" {
		t.Fatalf("down with a fixed site: %v, want P4202", err)
	}
	mustExec(t, pool, `UPDATE aggregated_edge_site_schedules SET strategy='failover' WHERE site_id=$1`, site)

	mustExec(t, pool, `INSERT INTO aggregated_edge_line_targets(site_id,line_scope,kind,supply_id,target,since,next_publish_at,updated_at)
		VALUES($1,'',  'third_party_cdn',$2,'cf.fixed-420.test',$3,$3,$3)`, site, supply, now)
	if _, err := pool.Exec(ctx, `UPDATE aggregated_edge_line_targets SET alert='degraded' WHERE site_id=$1`, site); sqlState(err) != "23514" {
		t.Fatalf("unknown alert: %v, want check violation", err)
	}
	mustExec(t, pool, `UPDATE aggregated_edge_line_targets SET alert='current_unhealthy' WHERE site_id=$1`, site)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4202" {
		t.Fatalf("down with a current_unhealthy alert: %v, want P4202", err)
	}
	mustExec(t, pool, `UPDATE aggregated_edge_line_targets SET alert='' WHERE site_id=$1`, site)

	mustExec(t, pool, `UPDATE aggregated_edge_line_targets SET alert='origin_unhealthy',alert_kept=true WHERE site_id=$1`, site)
	mustExec(t, pool, `UPDATE aggregated_edge_line_targets SET alert='edge_all_unhealthy',alert_kept=false WHERE site_id=$1`, site)
	mustExec(t, pool, `UPDATE aggregated_edge_line_targets SET alert='' WHERE site_id=$1`, site)
	mustExec(t, pool, `UPDATE aggregated_edge_site_schedules SET freeze_kept=true WHERE site_id=$1`, site)
	var policy, templates int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_event_policies WHERE event_type='aggregated_edge.schedule.alert'),
		(SELECT count(*) FROM notification_templates WHERE template_id='aggregated_edge.schedule.alert.zh-cn')`).Scan(&policy, &templates); err != nil ||
		policy != 1 || templates != 2 {
		t.Fatalf("notification policy=%d templates=%d, %v", policy, templates, err)
	}

	mustExec(t, pool, `INSERT INTO aggregated_edge_switch_events(id,site_id,line_scope,reason,created_at)
		VALUES($1,$2,'','origin_unhealthy',$3)`, uuid.New(), site, now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4202" {
		t.Fatalf("down with origin_unhealthy history: %v, want P4202", err)
	}
}
