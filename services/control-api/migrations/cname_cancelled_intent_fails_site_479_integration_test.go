//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestCNAMECancelledIntentFailsSite479: 479 up, down and
// up again apply on the 478 head; after up the site CNAME check accepts a
// cancelled intent job (and requires failed), after down it is the 412 body.
func TestCNAMECancelledIntentFailsSite479(t *testing.T) {
	const version = 479
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	body := func() string {
		t.Helper()
		var source string
		if err := pool.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE proname='validate_sites_cname_authority_113'`).Scan(&source); err != nil {
			t.Fatal(err)
		}
		return source
	}
	const accepted = "job.state IN ('queued','running','failed','cancelled')"
	for _, step := range []struct {
		direction string
		cancelled bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := strings.Contains(body(), accepted); got != step.cancelled {
			t.Fatalf("after %s: cancelled intent accepted=%v, want %v", step.direction, got, step.cancelled)
		}
	}
}
