//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

func autoDefenseStoreVersion(t *testing.T) int64 {
	t.Helper()
	matches, err := fs.Glob(controlmigrations.FS, "*_autodefense_store.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("autodefense store migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// TestAutoDefenseStore403: up/down/up; site rows belong to the site's own
// tenant scope; one active event per site; a signature from a node names
// the node; deleting a site removes its rows; down refuses while settings or
// mitigations in force exist.
func TestAutoDefenseStore403(t *testing.T) {
	version := autoDefenseStoreVersion(t)
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	tenantID, otherTenantID, scopeID, otherScopeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	userID, siteID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, pair := range [][2]uuid.UUID{{tenantID, scopeID}, {otherTenantID, otherScopeID}} {
		mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'403 tenant')`, pair[0])
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, pair[1], pair[0])
	}
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ad-403','AD 403','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	seedSite335(ctx, t, pool, scopeID, userID, siteID, 1)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,display_id,name,admin_state,created_by_user_id) VALUES($1,$2,40101,'ad-403','active',$3)`,
		nodeID, scopeID, userID)

	site := `INSERT INTO autodefense_sites(tenant_scope_id,site_id,mode,sensitivity,maturity,cross_site,circuit_state,
		circuit_manual_resume,max_level,modules,revision,updated_at)
		VALUES($1,$2,'protect','medium','prior',false,'closed',false,'{"field":"site.max_level"}','[]',1,now())`
	if _, err := pool.Exec(ctx, site, otherScopeID, siteID); sqlState(err) != "23503" {
		t.Fatalf("site row in another scope: %v, want 23503", err)
	}
	mustExec(t, pool, site, scopeID, siteID)

	event := `INSERT INTO autodefense_events(id,tenant_scope_id,site_id,status,started_at,peak_level,steps,updated_at)
		VALUES($1,$2,$3,'active',now(),1,'[]',now())`
	mustExec(t, pool, event, uuid.New(), scopeID, siteID)
	if _, err := pool.Exec(ctx, event, uuid.New(), scopeID, siteID); sqlState(err) != "23505" {
		t.Fatalf("second active event: %v, want 23505", err)
	}
	signature := `INSERT INTO autodefense_signatures(tenant_scope_id,site_id,id,conditions,stage,cover_permille,fpr_ppm,hits,reason,
		origin,origin_node_id,managed,revoked,created_at,updated_at)
		VALUES($1,$2,'0123456789abcdef','[{}]','shadow',100,10,0,'mined','node',$3,true,false,now(),now())`
	if _, err := pool.Exec(ctx, signature, scopeID, siteID, nil); sqlState(err) != "23514" {
		t.Fatalf("node signature without node: %v, want 23514", err)
	}
	mustExec(t, pool, signature, scopeID, siteID, nodeID)
	mitigation := `INSERT INTO autodefense_mitigations(id,tenant_scope_id,site_id,kind,target,level,scope,offences,score,reason,
		last_node_id,since,until,updated_at) VALUES($1,$2,$3,'ip','198.51.100.7',3,'site',1,80,'rate',$4,now(),now()+interval '10 minutes',now())`
	mustExec(t, pool, mitigation, uuid.New(), scopeID, siteID, nodeID)
	mustExec(t, pool, `INSERT INTO autodefense_report_receipts(node_id,report_scope,seq,kind,outcome,received_at)
		VALUES($1,$2,1,'verdicts','applied',now())`, nodeID, "site:"+siteID.String())
	if _, err := pool.Exec(ctx, `INSERT INTO autodefense_report_receipts(node_id,report_scope,seq,kind,outcome,received_at)
		VALUES($1,$2,1,'verdicts','applied',now())`, nodeID, "site:"+siteID.String()); sqlState(err) != "23505" {
		t.Fatalf("duplicate receipt: %v, want 23505", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4032" {
		t.Fatalf("down with settings: %v, want P4032", err)
	}
	mustExec(t, pool, `UPDATE sites SET deleted_at=now() WHERE id=$1`, siteID)
	mustExec(t, pool, `DELETE FROM autodefense_sites`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4032" {
		t.Fatalf("down with a mitigation in force: %v, want P4032", err)
	}
	mustExec(t, pool, `UPDATE autodefense_mitigations SET released_at=now(),released_by='user:x'`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
}
