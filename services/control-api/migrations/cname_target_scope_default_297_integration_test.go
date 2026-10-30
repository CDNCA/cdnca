//go:build integration

package migrations_test

import "testing"

// TestCNAMETargetScopeDefaultMigration rolls the default up, down and up
// again on a 296 schema. 349 drops it again (no pre-287 writer in 1.0.35).
func TestCNAMETargetScopeDefaultMigration(t *testing.T) {
	const version = 297
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var triggers []string
	if err := pool.QueryRow(ctx, `SELECT array_agg(tgname::text ORDER BY tgname) FROM pg_trigger
		WHERE tgrelid='cname_allocation_targets'::regclass AND NOT tgisinternal AND tgtype & 4 = 4`).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	// The default runs before the 287 scope guard.
	if len(triggers) < 2 || triggers[0] != "a_cname_allocation_targets_scope_297" ||
		triggers[1] != "cname_allocation_targets_node_group_287" {
		t.Fatalf("INSERT triggers = %v", triggers)
	}
}
