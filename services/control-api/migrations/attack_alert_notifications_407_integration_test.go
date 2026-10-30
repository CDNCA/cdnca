//go:build integration

package migrations_test

import "testing"

// TestAttackAlertNotifications407: the event policy, templates and state
// tables come and go with the migration; down refuses once notices exist.
func TestAttackAlertNotifications407(t *testing.T) {
	const version = 407
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policies, templates int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM notification_event_policies WHERE event_type='security.attack.detected' AND enabled AND supported AND default_email),
		(SELECT count(*) FROM notification_templates WHERE template_id='security.attack.detected.zh-cn')`).Scan(&policies, &templates); err != nil ||
		policies != 1 || templates != 2 {
		t.Fatalf("policy=%d templates=%d err=%v", policies, templates, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO attack_alert_cursor(singleton,evaluated_through,updated_at) VALUES(false,now(),now())`); sqlState(err) != "23514" {
		t.Fatalf("second cursor row: %v, want 23514", err)
	}
	mustExec(t, pool, `ALTER TABLE notification_events DISABLE TRIGGER USER`)
	if _, err := pool.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
		request_digest,created_at) VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'attack-alert/x/1',
		'security.attack.detected','tenant_subscribed',decode(repeat('00',32),'hex'),now())`)
	if _, err := pool.Exec(ctx, `SET session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4072" {
		t.Fatalf("down with notices: %v, want P4072", err)
	}
}
