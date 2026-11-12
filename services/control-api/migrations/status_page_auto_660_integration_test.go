//go:build integration

package migrations_test

import "testing"

// TestStatusPageAuto660UpDownUp rolls the hidden column, the
// lines_synced_at column and the seen table up, down and up on the 659 head.
func TestStatusPageAuto660UpDownUp(t *testing.T) {
	const version = 660
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	objects := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='status_page_components'
			  AND column_name='hidden' AND data_type='boolean' AND is_nullable='NO')
			+ (SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='status_page_settings'
			  AND column_name='lines_synced_at')
			+ (SELECT count(*) FROM information_schema.tables
			WHERE table_schema=current_schema() AND table_name='status_page_line_group_seen')`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if got := objects(); got != 0 {
		t.Fatalf("before up: %d objects, want 0", got)
	}
	for _, step := range []struct {
		direction string
		want      int
	}{{"up", 3}, {"down", 0}, {"up", 3}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := objects(); got != step.want {
			t.Fatalf("after %s: %d objects, want %d", step.direction, got, step.want)
		}
	}
	// A second up on the 660 head skips the applied version and changes nothing.
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("repeat up %d: %v", version, err)
	}
	if got := objects(); got != 3 {
		t.Fatalf("after repeat up: %d objects, want 3", got)
	}
}
