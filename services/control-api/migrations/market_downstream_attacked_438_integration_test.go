//go:build integration

package migrations_test

import "testing"

// TestMarketDownstreamAttacked438 rolls 438 up, down and up and checks the
// event is subscribable with its two templates.
func TestMarketDownstreamAttacked438(t *testing.T) {
	const version = 438
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var policies, templates int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_event_policies WHERE event_type='market.downstream.attacked'
			AND enabled AND supported AND default_email AND NOT default_sms),
		(SELECT count(*) FROM notification_templates WHERE template_id='market.downstream.attacked.zh-cn')`).Scan(&policies, &templates); err != nil ||
		policies != 1 || templates != 2 {
		t.Fatalf("policies=%d templates=%d, %v", policies, templates, err)
	}
}
