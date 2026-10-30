//go:build integration

package migrations_test

import "testing"

// TestWAFQuickBlockMigration rolls 344 up, down and up: the quick_block
// column (WAF only) and the quick block write operation exist only while it
// is applied; a down drops recorded quick block writes first.
func TestWAFQuickBlockMigration(t *testing.T) {
	const version = 344
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var column, operation bool
		if err := pool.QueryRow(t.Context(), `SELECT
			EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
			  AND table_name='security_policies' AND column_name='quick_block'),
			EXISTS(SELECT 1 FROM pg_constraint WHERE conname='security_policy_write_requests_operation_check'
			  AND pg_get_constraintdef(oid) LIKE '%security_policy.quick_block%')`).Scan(&column, &operation); err != nil {
			t.Fatal(err)
		}
		if want := step == "up"; column != want || operation != want {
			t.Fatalf("after %s: column=%v operation=%v", step, column, operation)
		}
	}
}
