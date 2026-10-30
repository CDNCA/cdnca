//go:build integration

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestNodeSecurityWAFBanAlerts452 rolls 452 up, down and up, checks the
// notification event is seeded, and that down refuses once a message uses
// its template.
func TestNodeSecurityWAFBanAlerts452(t *testing.T) {
	const version = 452
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policy, templates int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_event_policies WHERE event_type='node.security.waf_ban'
			AND enabled AND supported AND default_email AND NOT default_sms),
		(SELECT count(*) FROM notification_templates WHERE template_id='node.security.waf_ban.zh-cn')`).Scan(&policy, &templates); err != nil ||
		policy != 1 || templates != 2 {
		t.Fatalf("notification policy=%d templates=%d, %v", policy, templates, err)
	}

	platform, user, event := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'waf-452','WAF 452','unused')`, user)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platform, user)
	mustExec(t, pool, `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at)
		VALUES($1,$2,$3,'waf-ban/test','node.security.waf_ban','system_required',decode(repeat('00',32),'hex'),$4)`, event, platform, user, now)
	mustExec(t, pool, `INSERT INTO notification_outbox(id,scope_id,event_id,channel,template_id,template_version,subject,body,dedup_key,
		status,attempt_count,available_at,created_at,updated_at,generation)
		VALUES($1,$2,$3,'email','node.security.waf_ban.zh-cn',1,'s','b',$4,'pending',0,$5,$5,$5,1)`,
		uuid.New(), platform, event, "notification-v1-"+strings.Repeat("b", 64), now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4522" {
		t.Fatalf("down with a queued WAF ban message: %v, want P4522", err)
	}
}
