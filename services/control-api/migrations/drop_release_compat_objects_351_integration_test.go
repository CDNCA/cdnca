//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDropReleaseCompatObjects351: 351 drops 297's pre-287 writer default
// (trigger and function) and 306's dead compatible_challenge column; down
// restores both exactly, and up runs again.
func TestDropReleaseCompatObjects351(t *testing.T) {
	const version = 351
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	assertReleaseCompatObjects351(ctx, t, pool, true)
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", false}, {"down", true}, {"up", false}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		assertReleaseCompatObjects351(ctx, t, pool, step.present)
	}
}

func assertReleaseCompatObjects351(ctx context.Context, t *testing.T, pool *pgxpool.Pool, present bool) {
	t.Helper()
	var trigger, function, column bool
	if err := pool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='cname_allocation_targets'::regclass AND
			tgname='a_cname_allocation_targets_scope_297'),
		to_regprocedure(current_schema() || '.default_cname_target_node_group_scope_297()') IS NOT NULL,
		EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='security_activation_capability_waits'::regclass AND
			attname='compatible_challenge' AND NOT attisdropped)`).Scan(&trigger, &function, &column); err != nil {
		t.Fatal(err)
	}
	if trigger != present || function != present || column != present {
		t.Fatalf("trigger=%t function=%t column=%t, want all %t", trigger, function, column, present)
	}
	// 287's scope guard stays in place either way.
	var guard bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE
		tgrelid='cname_allocation_targets'::regclass AND tgname='cname_allocation_targets_node_group_287')`).Scan(&guard); err != nil {
		t.Fatal(err)
	}
	if !guard {
		t.Fatal("287 node group guard missing")
	}
}
