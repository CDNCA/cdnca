//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestAutoDefenseFederation415: up/down/up; a pre-415 solidify link (no rule
// written) returns to automatic management and the origin node becomes a
// sighting; ban list source autodefense is accepted only while 415 is
// applied; down refuses while a signature is solidified into a user pack.
func TestAutoDefenseFederation415(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_autodefense_federation.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("federation migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, nodeID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'415 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ad-415','AD 415','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,display_id,name,admin_state,created_by_user_id) VALUES($1,$2,41401,'ad-415','active',$3)`,
		nodeID, scopeID, userID)
	seedSite335(ctx, t, pool, scopeID, userID, siteID, 1)
	mustExec(t, pool, `INSERT INTO autodefense_signatures(tenant_scope_id,site_id,id,conditions,stage,cover_permille,fpr_ppm,hits,reason,
		origin,origin_node_id,managed,solidified_kind,solidified_rule_id,revoked,created_at,updated_at)
		VALUES($1,$2,'00000000000000aa','[{"dim":"method","value":"POST"}]','shadow',700,100,300,'pre 415','node',$3,false,'waf',$4,false,now(),now())`,
		scopeID, siteID, nodeID, uuid.New())

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	var managed bool
	var evaluation string
	var sightings int
	if err := pool.QueryRow(ctx, `SELECT managed, evaluation, (SELECT count(*) FROM autodefense_signature_sightings WHERE node_id=$1)
		FROM autodefense_signatures WHERE id='00000000000000aa'`, nodeID).Scan(&managed, &evaluation, &sightings); err != nil ||
		!managed || evaluation != "pending" || sightings != 1 {
		t.Fatalf("pre-415 row: managed=%v evaluation=%s sightings=%d %v", managed, evaluation, sightings, err)
	}
	insertBan := `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until,source_event_id)
		VALUES($1::uuid,$2,$3,'198.51.100.7','autodefense',now(),now()+interval '10 minutes','autodefense:'||$1::uuid::text)`
	mustExec(t, pool, insertBan, uuid.New(), scopeID, siteID)
	if _, err := pool.Exec(ctx, `UPDATE autodefense_signatures SET solidified_kind='waf' WHERE id='00000000000000aa'`); sqlState(err) != "23514" {
		t.Fatalf("solidified kind without pack: %v, want 23514", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE autodefense_signatures SET evaluation='promoted' WHERE id='00000000000000aa'`); sqlState(err) != "23514" {
		t.Fatalf("unknown evaluation: %v, want 23514", err)
	}
	mustExec(t, pool, `UPDATE autodefense_signatures SET managed=false, solidified_kind='waf', solidified_rule_id=$1,
		solidified_pack_id='user/x/autodefense-00000000000000aa', solidified_version='1.0.0' WHERE id='00000000000000aa'`, uuid.New())
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4152" {
		t.Fatalf("down with a solidified signature: %v, want P4152", err)
	}
	mustExec(t, pool, `UPDATE autodefense_signatures SET managed=true, solidified_kind=NULL, solidified_rule_id=NULL,
		solidified_pack_id=NULL, solidified_version=NULL WHERE id='00000000000000aa'`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	var bans int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_ban_entries`).Scan(&bans); err != nil || bans != 0 {
		t.Fatalf("down keeps autodefense bans: %d %v", bans, err)
	}
	if _, err := pool.Exec(ctx, insertBan, uuid.New(), scopeID, siteID); sqlState(err) != "23514" {
		t.Fatalf("source autodefense before 415: %v, want 23514", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
