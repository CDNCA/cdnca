//go:build integration

package migrations_test

import (
	"slices"
	"testing"
)

// 642 adds the local alias/note columns and their CHECKs: down restores the 641 schema object for object, up again rebuilds
// the same head.
func TestMarketLocalLabels642UpDownUp(t *testing.T) {
	const version = 642
	pool := migrationPoolAt(t, version-1)
	before := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	applied := migrationSchemaFingerprint(t, pool)
	if slices.Equal(before, applied) {
		t.Fatal("up 642 changed no schema object")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertMigrationSchemaEqual(t, "down 642 vs 641", before, migrationSchemaFingerprint(t, pool))
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	assertMigrationSchemaEqual(t, "up again 642 vs first up", applied, migrationSchemaFingerprint(t, pool))
}
