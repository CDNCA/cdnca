//go:build integration

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestMarketNodeActions440 rolls 440 up, down and up, checks the queue and
// the three events (email on, SMS off), and that down refuses once a message
// uses one of their templates or an action is still unreported.
func TestMarketNodeActions440(t *testing.T) {
	const version = 440
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policies, templates int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_event_policies
			WHERE event_type IN ('market.node.action','market.site.paused','market.site.resumed')
			AND enabled AND supported AND default_email AND NOT default_sms),
		(SELECT count(*) FROM notification_templates WHERE template_id IN
			('market.node.action.zh-cn','market.site.paused.zh-cn','market.site.resumed.zh-cn'))`).Scan(&policies, &templates); err != nil ||
		policies != 3 || templates != 6 {
		t.Fatalf("policies=%d templates=%d, %v", policies, templates, err)
	}
	// A site row must be an automatic defence L4/L5 verdict with its market key.
	if _, err := pool.Exec(ctx, `INSERT INTO market_node_action_queue(node_id,node_pool_ref,occurred_at,source,kind,level,count,
		market_key,site_id,created_at) VALUES($1,'pool',now(),'ddos','rate_ban',4,1,repeat('a',24),$1,now())`, uuid.New()); sqlState(err) != "23514" {
		t.Fatalf("a ddos row with a site: %v, want 23514", err)
	}
	mustExec(t, pool, `INSERT INTO market_node_action_queue(node_id,node_pool_ref,occurred_at,source,kind,level,count,created_at)
		VALUES($1,'pool','2026-10-22T00:00:00Z','ddos','rate_ban',4,1,now())`, uuid.New())
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4403" {
		t.Fatalf("down with an unreported node action: %v, want P4403", err)
	}
	platform, user, event := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'mkt-440','Mkt 440','unused')`, user)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platform, user)
	mustExec(t, pool, `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at)
		VALUES($1,$2,$3,'market-notice/test','market.node.action','tenant_subscribed',decode(repeat('00',32),'hex'),$4)`, event, platform, user, now)
	mustExec(t, pool, `INSERT INTO notification_outbox(id,scope_id,event_id,channel,template_id,template_version,subject,body,dedup_key,
		status,attempt_count,available_at,created_at,updated_at,generation)
		VALUES($1,$2,$3,'email','market.node.action.zh-cn',1,'s','b',$4,'pending',0,$5,$5,$5,1)`,
		uuid.New(), platform, event, "notification-v1-"+strings.Repeat("a", 64), now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4402" {
		t.Fatalf("down with a queued market message: %v, want P4402", err)
	}
}
