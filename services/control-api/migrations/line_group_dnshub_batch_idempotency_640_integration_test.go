//go:build integration

package migrations_test

import (
	"slices"
	"testing"
)

// 640 widens one CHECK and adds the DNS hub batch table: down restores the 639 schema object for object, up again rebuilds the
// same head.
func TestLineGroupDNSHubBatchIdempotency640UpDownUp(t *testing.T) {
	const version = 640
	pool := migrationPoolAt(t, version-1)
	before := migrationSchemaFingerprint(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	applied := migrationSchemaFingerprint(t, pool)
	if slices.Equal(before, applied) {
		t.Fatal("up 640 changed no schema object")
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertMigrationSchemaEqual(t, "down 640 vs 639", before, migrationSchemaFingerprint(t, pool))
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	assertMigrationSchemaEqual(t, "up again 640 vs first up", applied, migrationSchemaFingerprint(t, pool))
}
