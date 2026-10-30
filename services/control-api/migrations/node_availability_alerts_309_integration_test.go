//go:build integration

package migrations_test

import "testing"

// TestNodeAvailabilityAlerts309RollbackFrom310 rolls 310 and 309 down from a
// 310 schema and back up. 309 down deletes seeded notification_templates rows,
// which the immutable trigger rejects unless the rollback disables it around
// the delete; the trigger must be enabled again afterwards.
func TestNodeAvailabilityAlerts309RollbackFrom310(t *testing.T) {
	pool := migrationPoolAt(t, 310)
	ctx := t.Context()
	counts := func() (templates, policies int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM notification_templates
			 WHERE template_id IN ('node.availability.offline.zh-cn', 'node.availability.recovered.zh-cn')),
			(SELECT count(*) FROM notification_event_policies
			 WHERE event_type IN ('node.availability.offline', 'node.availability.recovered'))`).Scan(&templates, &policies); err != nil {
			t.Fatal(err)
		}
		return templates, policies
	}
	triggerEnabled := func() bool {
		t.Helper()
		var enabled bool
		if err := pool.QueryRow(ctx, `SELECT tgenabled='O' FROM pg_trigger
			WHERE tgrelid='notification_templates'::regclass AND tgname='notification_templates_immutable'`).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		return enabled
	}
	if templates, policies := counts(); templates == 0 || policies != 2 {
		t.Fatalf("before rollback templates=%d policies=%d", templates, policies)
	}
	for _, step := range []struct {
		direction string
		version   int64
	}{{"down", 310}, {"down", 309}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, step.version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, step.version, err)
		}
	}
	if templates, policies := counts(); templates != 0 || policies != 0 {
		t.Fatalf("after rollback templates=%d policies=%d", templates, policies)
	}
	if !triggerEnabled() {
		t.Fatal("notification_templates_immutable left disabled after 309 down")
	}
	for _, version := range []int64{309, 310} {
		if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
			t.Fatalf("up %d: %v", version, err)
		}
	}
	if templates, policies := counts(); templates == 0 || policies != 2 {
		t.Fatalf("after re-apply templates=%d policies=%d", templates, policies)
	}
}
