//go:build integration

package migrations_test

import (
	"slices"
	"testing"
)

// 638 adds only the batch idempotency table: down restores the 637 schema object for object, up again rebuilds the
// same head.
func TestSecurityPolicyBatchIdempotency638UpDownUp(t *testing.T) {
	const version = 638
	pool := migrationPoolAt(t, version-1)
	before := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	applied := migrationSchemaFingerprint(t, pool)
	if slices.Equal(before, applied) {
		t.Fatal("up 638 changed no schema object")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertMigrationSchemaEqual(t, "down 638 vs 637", before, migrationSchemaFingerprint(t, pool))
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	assertMigrationSchemaEqual(t, "up again 638 vs first up", applied, migrationSchemaFingerprint(t, pool))
}
