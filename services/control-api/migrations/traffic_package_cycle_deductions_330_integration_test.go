//go:build integration

package migrations_test

import "testing"

// TestTrafficPackageCycleDeductionsMigration rolls 330 up, down and up; the
// table and the due-grant index only exist while it is applied.
func TestTrafficPackageCycleDeductionsMigration(t *testing.T) {
	const version = 330
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var table, index bool
		if err := pool.QueryRow(t.Context(), `SELECT
			to_regclass(current_schema()||'.traffic_package_cycle_deductions') IS NOT NULL,
			to_regclass(current_schema()||'.traffic_package_grants_due_330') IS NOT NULL`).Scan(&table, &index); err != nil {
			t.Fatal(err)
		}
		if want := step == "up"; table != want || index != want {
			t.Fatalf("after %s: table=%v index=%v", step, table, index)
		}
	}
}
