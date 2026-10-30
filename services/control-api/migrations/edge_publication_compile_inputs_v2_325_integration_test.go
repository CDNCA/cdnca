//go:build integration

package migrations_test

import "testing"

// TestEdgePublicationCompileInputsV2Migration rolls 325 up, down and up.
func TestEdgePublicationCompileInputsV2Migration(t *testing.T) {
	const version = 325
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
}
