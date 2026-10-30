//go:build integration

package migrations_test

import "testing"

// TestRechargePaymentLegacyReconcileDropMigration rolls 357 up, down and up:
// the 152 reconcile queue disappears and comes back empty, and the shared
// append-only guard of the remaining 152 tables survives.
func TestRechargePaymentLegacyReconcileDropMigration(t *testing.T) {
	const version = 357
	pool := migrationPoolAt(t, version-1)
	state := func() (jobs, receipts, guard, factGuard bool) {
		t.Helper()
		if err := pool.QueryRow(t.Context(), `SELECT
			to_regclass('recharge_payment_reconcile_jobs_v1') IS NOT NULL,
			to_regclass('recharge_payment_reconcile_receipts_v1') IS NOT NULL,
			to_regprocedure('guard_recharge_payment_reconcile_job_152()') IS NOT NULL,
			EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='recharge_payment_commands_v1'::regclass
				AND tgname='recharge_payment_commands_append_only_v1')`).Scan(&jobs, &receipts, &guard, &factGuard); err != nil {
			t.Fatal(err)
		}
		return jobs, receipts, guard, factGuard
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		jobs, receipts, guard, factGuard := state()
		present := step == "down"
		if jobs != present || receipts != present || guard != present || !factGuard {
			t.Fatalf("after %s jobs=%v receipts=%v guard=%v fact_guard=%v", step, jobs, receipts, guard, factGuard)
		}
	}
}
