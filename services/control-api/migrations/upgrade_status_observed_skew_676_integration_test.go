//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// 676: 675 -> 676 -> 675 -> 676. The status receipt trigger accepts an observed_at up to
// 30 seconds before the command's published_at (a node observed its commands 27-29 ms before the
// outbox settlement, P9302 on every redelivery); the rest of the 105 trigger is unchanged.
func TestUpgradeStatusObservedSkew676UpDownUp(t *testing.T) {
	const version = 676
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	definition := func() string {
		t.Helper()
		var text string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_control_upgrade_status_105()'::regprocedure)`).
			Scan(&text); err != nil {
			t.Fatal(err)
		}
		return text
	}
	relaxed := func(text string) bool {
		return strings.Contains(text, "published_at - '00:00:30'::interval") ||
			strings.Contains(text, "published_at-interval '30 seconds'")
	}
	before := definition()
	if relaxed(before) || !strings.Contains(before, "NEW.observed_at<command_row.published_at OR") {
		t.Fatal("675 trigger does not carry the strict published_at bound")
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
			t.Fatalf("after %s: relaxed bound = %v", step.direction, !step.relaxed)
		}
		if step.direction == "down" && text != before {
			t.Fatal("676 down did not restore the 105 trigger exactly")
		}
	}
}
