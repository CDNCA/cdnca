//go:build integration

package migrations_test

import (
	"slices"
	"testing"
)

// 645 drops plugin_local_disables.reason: down restores the 644 schema object for object (the column, its NOT NULL and
// its 1..500 CHECK), up again rebuilds the same head.
func TestPluginLocalDisablesNoReason645UpDownUp(t *testing.T) {
	const version = 645
	pool := migrationPoolAt(t, version-1)
	before := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	applied := migrationSchemaFingerprint(t, pool)
	if slices.Equal(before, applied) {
		t.Fatal("up 645 changed no schema object")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertMigrationSchemaEqual(t, "down 645 vs 644", before, migrationSchemaFingerprint(t, pool))
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	assertMigrationSchemaEqual(t, "up again 645 vs first up", applied, migrationSchemaFingerprint(t, pool))
}
