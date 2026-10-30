//go:build integration

package migrations_test

import "testing"

// TestSystemRepublicationSecondaryVerificationMigration rolls 324 up, down and
// up on a 323 schema next to a sibling schema that already has the guarded
// constraints; the up then accepts the new trigger.
func TestSystemRepublicationSecondaryVerificationMigration(t *testing.T) {
	const version = 324
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	seedSiblingSchemaConstraints(t, pool, "edge_system_republication_heads_triggers_check",
		"edge_system_republication_attempts_triggers_check", "edge_system_revision_segments_source_check")
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var accepts bool
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) LIKE '%secondary_verification%'
		FROM pg_constraint WHERE connamespace=current_schema()::regnamespace
		  AND conname='edge_system_revision_segments_source_check'`).Scan(&accepts); err != nil || !accepts {
		t.Fatalf("segment source check accepts secondary_verification=%v err=%v", accepts, err)
	}
}
