//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestAggregatedEdgeSchedule366: a site with a third-party binding gets line
// targets; the shape checks hold (local only on the default line,
// follow_default never on it, a supply row carries its target); binding
// line scopes are the unified lines; up, down and up again.
func TestAggregatedEdgeSchedule366(t *testing.T) {
	const version = 366
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, siteID, platformID, supplyID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'366 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ae-366','AE 366','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,http_ports,https_ports,
			origins,origin_hosts,created_by_user_id,updated_by_user_id) VALUES($1,$2,1,$3,'ae366.example.com',ARRAY['80'],
			ARRAY['443'],ARRAY['origin.example.com:80'],ARRAY['origin.example.com'],$3,$3)`, siteID, scopeID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.com',80)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO site_supplies(id,platform_scope_id,kind,name,target,status,created_at,updated_at)
		VALUES($1,$2,'third_party_cdn','cf','edge.cdn.example.net','active',now(),now())`, supplyID, platformID)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	mustExec(t, pool, `INSERT INTO site_supply_bindings(site_id,supply_id,role,priority,line_scope,created_at)
		VALUES($1,$2,'primary',100,'overseas',now())`, siteID, supplyID)
	if _, err := pool.Exec(ctx, `INSERT INTO site_supply_bindings(site_id,supply_id,role,priority,line_scope,created_at)
		VALUES($1,$2,'primary',100,'境外',now())`, siteID, supplyID); sqlState(err) != "23514" {
		t.Fatalf("non-unified line scope: %v, want 23514", err)
	}
	insert := `INSERT INTO aggregated_edge_line_targets(site_id,line_scope,kind,supply_id,target,since,next_publish_at,updated_at)
		VALUES($1,$2,$3,$4,$5,now(),now(),now())`
	mustExec(t, pool, insert, siteID, "overseas", "third_party_cdn", supplyID, "edge.cdn.example.net")
	mustExec(t, pool, insert, siteID, "", "local", nil, "")
	for _, bad := range []struct {
		line, kind string
		supply     any
		target     string
	}{
		{"telecom", "local", nil, ""},                          // local is the default line's only
		{"telecom", "follow_default", supplyID, ""},            // follow_default has no supply
		{"mobile", "third_party_cdn", supplyID, ""},            // a supply row carries its target
		{"unicom", "third_party_cdn", nil, "edge.example.net"}, // and its supply
	} {
		if _, err := pool.Exec(ctx, insert, siteID, bad.line, bad.kind, bad.supply, bad.target); sqlState(err) != "23514" {
			t.Fatalf("%+v: %v, want 23514", bad, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE aggregated_edge_line_targets SET kind='follow_default',supply_id=NULL,target=''
		WHERE site_id=$1 AND line_scope=''`, siteID); sqlState(err) != "23514" {
		t.Fatalf("follow_default on the default line: %v, want 23514", err)
	}
	mustExec(t, pool, `INSERT INTO aggregated_edge_site_schedules(site_id,updated_at) VALUES($1,now())`, siteID)
	if _, err := pool.Exec(ctx, `UPDATE aggregated_edge_site_schedules SET frozen_at=now() WHERE site_id=$1`,
		siteID); sqlState(err) != "23514" {
		t.Fatalf("frozen without a reason: %v, want 23514", err)
	}
	mustExec(t, pool, `UPDATE aggregated_edge_site_schedules SET frozen_at=now(),frozen_reason='flap_limit' WHERE site_id=$1`, siteID)
	// Deleting the site removes its schedule, targets and health; the
	// switch history stays.
	mustExec(t, pool, `INSERT INTO aggregated_edge_switch_events(id,site_id,line_scope,reason,created_at)
		VALUES($1,$2,'overseas','failover',now())`, uuid.New(), siteID)
	mustExec(t, pool, `DELETE FROM site_supply_bindings WHERE site_id=$1`, siteID)
	mustExec(t, pool, `DELETE FROM sites WHERE id=$1`, siteID)
	var targets, events int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM aggregated_edge_line_targets WHERE site_id=$1),
		(SELECT count(*) FROM aggregated_edge_switch_events WHERE site_id=$1)`, siteID).Scan(&targets, &events); err != nil ||
		targets != 0 || events != 1 {
		t.Fatalf("after site delete targets=%d events=%d (%v)", targets, events, err)
	}
}
