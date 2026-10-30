//go:build integration

package migrations_test

import "testing"

// TestTrafficPackageCoverageWakeMigration rolls 338 up, down and up; the cycle
// bound columns and the wake trigger only exist while it is applied.
func TestTrafficPackageCoverageWakeMigration(t *testing.T) {
	const version = 338
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var column, trigger bool
		if err := pool.QueryRow(t.Context(), `SELECT
			EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
			  AND table_name='traffic_package_cycle_deductions' AND column_name='cycle_starts_at'),
			EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='traffic_package_grants_wake_enforcement_338')`).Scan(
			&column, &trigger); err != nil {
			t.Fatal(err)
		}
		if want := step == "up"; column != want || trigger != want {
			t.Fatalf("after %s: column=%v trigger=%v", step, column, trigger)
		}
	}
}
