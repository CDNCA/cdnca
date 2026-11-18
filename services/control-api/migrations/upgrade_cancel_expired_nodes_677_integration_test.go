//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// 677: 676 -> 677 -> 676 -> 677. The paused -> cancelled guard reads only the last
// status of each command: final statuses no longer block, and claimed or later ones stop blocking 15
// minutes after the grant expired. The predicate runs on real commands in controlupgrade
// (TestCancelPausedRolloutAfterExpiredCommandPostgres, TestCancelPausedRolloutPostgres).
func TestUpgradeCancelExpiredNodes677UpDownUp(t *testing.T) {
	const version = 677
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	definition := func() string {
		t.Helper()
		var text string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_control_upgrade_plan_093()'::regprocedure)`).
			Scan(&text); err != nil {
			t.Fatal(err)
		}
		return text
	}
	relaxed := func(text string) bool {
		return strings.Contains(text, "JOIN LATERAL") && strings.Contains(text, "'healthy','failed','rolled_back'") &&
			strings.Contains(text, "interval '15 minutes'") && strings.Contains(text, "P6753")
	}
	before := definition()
	if relaxed(before) || !strings.Contains(before, "status.state<>'accepted' OR") {
		t.Fatal("676 head does not carry the 675 cancel guard")
	}
	for _, step := range []struct {
		direction string
		relaxed   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		text := definition()
		if relaxed(text) != step.relaxed {
			t.Fatalf("after %s: relaxed guard = %v", step.direction, !step.relaxed)
		}
		if step.direction == "down" && text != before {
			t.Fatal("677 down did not restore the 675 trigger exactly")
		}
	}
}
