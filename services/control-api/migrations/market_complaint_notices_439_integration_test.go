//go:build integration

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestMarketComplaintNotices439 rolls 439 up, down and up, checks both events
// are seeded subscribable (email on, SMS off), and that down refuses once a
// message uses one of their templates.
func TestMarketComplaintNotices439(t *testing.T) {
	const version = 439
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policies, templates, others int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_event_policies WHERE event_type LIKE 'market.complaint.%'
			AND enabled AND supported AND default_email AND NOT default_sms),
		(SELECT count(*) FROM notification_templates WHERE template_id LIKE 'market.complaint.%.zh-cn'),
		(SELECT count(*) FROM notification_event_policies WHERE event_type LIKE 'market.%')`).Scan(&policies, &templates, &others); err != nil ||
		policies != 2 || templates != 4 || others != 17 {
		t.Fatalf("policies=%d templates=%d market=%d, %v", policies, templates, others, err)
	}
	platform, user, event := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'mkt-439','Mkt 439','unused')`, user)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platform, user)
	mustExec(t, pool, `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at)
		VALUES($1,$2,$3,'market-notice/test','market.complaint.resolved','tenant_subscribed',decode(repeat('00',32),'hex'),$4)`, event, platform, user, now)
	mustExec(t, pool, `INSERT INTO notification_outbox(id,scope_id,event_id,channel,template_id,template_version,subject,body,dedup_key,
		status,attempt_count,available_at,created_at,updated_at,generation)
		VALUES($1,$2,$3,'email','market.complaint.resolved.zh-cn',1,'s','b',$4,'pending',0,$5,$5,$5,1)`,
		uuid.New(), platform, event, "notification-v1-"+strings.Repeat("b", 64), now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4392" {
		t.Fatalf("down with a queued complaint message: %v, want P4392", err)
	}
}
