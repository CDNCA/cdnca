//go:build integration

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestBanListTruncation461 rolls 461 up, down and up, checks the warning
// columns (warning and count go together) and the notification event, and
// that down refuses once a message uses its template.
func TestBanListTruncation461(t *testing.T) {
	const version = 461
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policy, templates, columns int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_event_policies WHERE event_type='node.security.list_truncated'
			AND enabled AND supported AND default_email AND NOT default_sms),
		(SELECT count(*) FROM notification_templates WHERE template_id='node.security.list_truncated.zh-cn'),
		(SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
			AND table_name IN ('security_ban_node_state','escalate_site_drop_node_states')
			AND column_name IN ('warning_code','truncated_entries'))`).Scan(&policy, &templates, &columns); err != nil ||
		policy != 1 || templates != 2 || columns != 4 {
		t.Fatalf("policy=%d templates=%d columns=%d, %v", policy, templates, columns, err)
	}
	for _, table := range []string{"security_ban_node_state", "escalate_site_drop_node_states"} {
		var check string
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1`,
			table+"_truncation_check").Scan(&check); err != nil || !strings.Contains(check, "truncated_entries = 0") {
			t.Fatalf("%s truncation check = %q %v", table, check, err)
		}
	}
	platform, user, event := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'trunc-461','Trunc 461','unused')`, user)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platform, user)
	mustExec(t, pool, `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at)
		VALUES($1,$2,$3,'list-truncated/test','node.security.list_truncated','system_required',decode(repeat('00',32),'hex'),$4)`,
		event, platform, user, now)
	mustExec(t, pool, `INSERT INTO notification_outbox(id,scope_id,event_id,channel,template_id,template_version,subject,body,dedup_key,
		status,attempt_count,available_at,created_at,updated_at,generation)
		VALUES($1,$2,$3,'email','node.security.list_truncated.zh-cn',1,'s','b',$4,'pending',0,$5,$5,$5,1)`,
		uuid.New(), platform, event, "notification-v1-"+strings.Repeat("c", 64), now)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4612" {
		t.Fatalf("down with a queued truncation message: %v, want P4612", err)
	}
}
