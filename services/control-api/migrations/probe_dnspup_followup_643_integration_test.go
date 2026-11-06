//go:build integration

package migrations_test

import (
	"slices"
	"testing"
)

// 643 adds the retention delete guard, its grants and probe_dnspup_purposes.probe_type: down restores the 642 schema object
// for object, up again rebuilds the same head.
func TestProbeDNSPupFollowup643UpDownUp(t *testing.T) {
	const version = 643
	pool := migrationPoolAt(t, version-1)
	before := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	applied := migrationSchemaFingerprint(t, pool)
	if slices.Equal(before, applied) {
		t.Fatal("up 643 changed no schema object")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertMigrationSchemaEqual(t, "down 643 vs 642", before, migrationSchemaFingerprint(t, pool))
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	assertMigrationSchemaEqual(t, "up again 643 vs first up", applied, migrationSchemaFingerprint(t, pool))
}
