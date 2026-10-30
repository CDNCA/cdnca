//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestWAFSubscriptionRulePacks359: up, down and up; a subscriber pack must
// live in the subscribing tenant's namespace; source 'subscription' exists
// only while 359 is applied; rollback refuses to drop subscriber packs and
// deleting the pack ends the subscription.
func TestWAFSubscriptionRulePacks359(t *testing.T) {
	const version = 359
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	tenantID, otherTenant, scopeID, otherScope := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	userID, subID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'359 tenant'),($2,'359 other')`, tenantID, otherTenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`, scopeID, tenantID, otherScope, otherTenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'sub-359','Sub 359','unused')`, userID)
	mustExec(t, pool, `INSERT INTO waf_rule_subscriptions(id,name,source_url,interval_minutes,enabled,next_fetch_at,
		created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,'feed','https://feed.example/r.json',360,true,now(),$2,$2,now(),now())`,
		subID, userID)
	packID := "user/" + scopeID.String() + "/waf-sub-" + strings.ReplaceAll(subID.String(), "-", "")
	mustExec(t, pool, `INSERT INTO rule_packs(pack_id,layer,owner_scope_id,update_policy,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,'user',$2,'auto',$3,$3,now(),now())`, packID, scopeID, userID)
	mustExec(t, pool, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,
		source,state,downloaded_at,created_by_user_id,created_at)
		VALUES($1,'1.0.0','waf_v2',1,'feed',repeat('a',64),2,'{}'::bytea,'subscription','downloaded',now(),$2,now())`, packID, userID)
	membership := `INSERT INTO waf_rule_subscription_packs(subscription_id,tenant_scope_id,pack_id,subscribed_by_user_id,subscribed_at)
		VALUES($1,$2,$3,$4,now())`
	if _, err := pool.Exec(ctx, membership, subID, otherScope, packID, userID); sqlState(err) != "23514" {
		t.Fatalf("pack of another tenant: %v, want 23514", err)
	}
	mustExec(t, pool, membership, subID, scopeID, packID, userID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback dropped a subscriber pack")
	}
	mustExec(t, pool, `DELETE FROM rule_packs WHERE pack_id=$1`, packID)
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM waf_rule_subscription_packs`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("membership after pack delete: %d (%v)", left, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down without subscriber packs: %v", err)
	}
}
