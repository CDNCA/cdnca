//go:build integration

package migrations_test

import "testing"

// TestEdgePublicationCompileInputsMigration rolls 318 up, down and up.
func TestEdgePublicationCompileInputsMigration(t *testing.T) {
	const version = 318
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
}
