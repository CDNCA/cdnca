//go:build integration

package migrations_test

import "testing"

// TestNodeLineEndpointPublishedMigration rolls 312 up, down and up on a 311 schema.
func TestNodeLineEndpointPublishedMigration(t *testing.T) {
	const version = 312
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_app','node_line_endpoint_published','SELECT') AND
		has_table_privilege('cdnca_control_runtime','node_line_endpoint_published','SELECT') AND
		NOT has_table_privilege('cdnca_control_app','node_line_endpoint_published','INSERT')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants = %v (%v)", granted, err)
	}
}
