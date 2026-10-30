//go:build integration

package migrations_test

import "testing"

// TestSiteCRSOverridesMigration rolls 374 up, down and up: the override and
// write request tables exist only while it is applied.
func TestSiteCRSOverridesMigration(t *testing.T) {
	const version = 374
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var overrides, writes bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass('site_crs_overrides') IS NOT NULL,
			to_regclass('site_crs_write_requests') IS NOT NULL`).Scan(&overrides, &writes); err != nil {
			t.Fatal(err)
		}
		if want := step == "up"; overrides != want || writes != want {
			t.Fatalf("after %s: overrides=%v writes=%v", step, overrides, writes)
		}
	}
}
