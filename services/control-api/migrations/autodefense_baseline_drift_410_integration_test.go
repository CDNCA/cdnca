//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestAutoDefenseBaselineDrift410: up/down/up; drift receipts and drift rows
// are accepted, unknown metrics refused; down removes the drift receipts so
// the restored kind check holds.
func TestAutoDefenseBaselineDrift410(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_autodefense_baseline_drift.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("baseline drift migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	tenantID, scopeID, userID, siteID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'410 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ad-410','AD 410','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	seedSite335(ctx, t, pool, scopeID, userID, siteID, 1)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,display_id,name,admin_state,created_by_user_id) VALUES($1,$2,40501,'ad-410','active',$3)`,
		nodeID, scopeID, userID)

	drift := `INSERT INTO autodefense_baseline_drifts(tenant_scope_id,site_id,node_id,metrics,days,reported_at) VALUES($1,$2,$3,$4,3,now())`
	if _, err := pool.Exec(ctx, drift, scopeID, siteID, nodeID, []string{"syn_rate"}); sqlState(err) != "23514" {
		t.Fatalf("unknown drift metric: %v, want 23514", err)
	}
	mustExec(t, pool, drift, scopeID, siteID, nodeID, []string{"ratio_404", "request_rate"})
	// The confirmation is all three columns or none.
	if _, err := pool.Exec(ctx, `UPDATE autodefense_baseline_drifts SET confirmed_by='user:x' WHERE node_id=$1`, nodeID); sqlState(err) != "23514" {
		t.Fatalf("partial confirmation: %v, want 23514", err)
	}
	mustExec(t, pool, `UPDATE autodefense_baseline_drifts SET confirmed_by='user:x',confirmed_at=now(),confirmed_metrics=metrics WHERE node_id=$1`, nodeID)
	mustExec(t, pool, `INSERT INTO autodefense_report_receipts(node_id,report_scope,seq,kind,outcome,received_at)
		VALUES($1,$2,1,'drift','applied',now())`, nodeID, "site:"+siteID.String())

	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with drift rows: %v", err)
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM autodefense_report_receipts`).Scan(&receipts); err != nil || receipts != 0 {
		t.Fatalf("receipts after down = %d, %v", receipts, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
