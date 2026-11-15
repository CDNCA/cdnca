//go:build integration

package migrations_test

import (
	"testing"
)

// 670: 669 -> 670 -> 669 -> 670. Up creates the recovery attempt and recovery failure
// tables and the security_activation.recovery_failed notification (policy + sms/email templates); down
// removes all of it.
func TestSecurityActivationRecoveryAttempts670UpDownUp(t *testing.T) {
	const version = 670
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	state := func() (bool, bool, int, int) {
		t.Helper()
		var attempts, failures bool
		var policies, templates int
		if err := pool.QueryRow(ctx, `SELECT
			to_regclass('security_activation_recovery_attempts_670') IS NOT NULL,
			to_regclass('security_activation_recovery_failures_670') IS NOT NULL,
			(SELECT count(*) FROM notification_event_policies WHERE event_type='security_activation.recovery_failed'),
			(SELECT count(*) FROM notification_templates WHERE template_id='security_activation.recovery_failed.zh-cn')`).
			Scan(&attempts, &failures, &policies, &templates); err != nil {
			t.Fatal(err)
		}
		return attempts, failures, policies, templates
	}
	if a, f, p, tm := state(); a || f || p != 0 || tm != 0 {
		t.Fatalf("before 670: attempts %v failures %v policies %d templates %d", a, f, p, tm)
	}
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		a, f, p, tm := state()
		want := 0
		if step.present {
			want = 1
		}
		if a != step.present || f != step.present || p != want || tm != 2*want {
			t.Fatalf("after %s: attempts %v failures %v policies %d templates %d", step.direction, a, f, p, tm)
		}
	}
}
