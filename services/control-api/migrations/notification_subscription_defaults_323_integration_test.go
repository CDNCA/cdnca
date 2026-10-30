//go:build integration

package migrations_test

import "testing"

// TestNotificationSubscriptionDefaults323Migration rolls 323 up, down and up
// on a 322 schema and checks the seeded defaults.
func TestNotificationSubscriptionDefaults323Migration(t *testing.T) {
	const version = 323
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var on, sms, staff int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE default_email), count(*) FILTER (WHERE default_sms),
		count(*) FILTER (WHERE event_type LIKE 'ticket.staff.%') FROM notification_event_policies`).Scan(&on, &sms, &staff); err != nil {
		t.Fatal(err)
	}
	// 3 package + 3 customer ticket + 2 operator ticket events default to email.
	if on != 8 || sms != 0 || staff != 2 {
		t.Fatalf("default_email=%d default_sms=%d staff=%d", on, sms, staff)
	}
	var renewSucceeded bool
	if err := pool.QueryRow(ctx, `SELECT default_email FROM notification_event_policies
		WHERE event_type='package.auto_renew.succeeded'`).Scan(&renewSucceeded); err != nil || renewSucceeded {
		t.Fatalf("auto_renew.succeeded default_email = %v (%v)", renewSucceeded, err)
	}
}
