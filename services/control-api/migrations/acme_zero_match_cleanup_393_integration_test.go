//go:build integration

package migrations_test

import "testing"

// TestACMEZeroMatchCleanup393RoundTrip: 393 applies on the exact 392 head and
// rolls back while no zero-match cleanup fact exists. The cleanup chain itself
// is exercised by acmeworker's TestPGDNSZeroMatchCleanup* tests at the head.
func TestACMEZeroMatchCleanup393RoundTrip(t *testing.T) {
	const version = 393
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
}
