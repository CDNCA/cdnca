//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestBillingAdjustmentMFAWaiver615: up adds the waiver
// columns and the either-proof-or-waiver CHECK, down restores the 614 shape;
// a forged waiver without its mfa.step_up.waive audit is refused.
func TestBillingAdjustmentMFAWaiver615(t *testing.T) {
	// Keep equal to the migration's version (renum-one.sh rewrites it).
	const version = 615
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var nullable string
	if err := pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='billing_adjustment_requests'
		  AND column_name='proposed_step_up_proof_id'`).Scan(&nullable); err != nil || nullable != "YES" {
		t.Fatalf("proposed_step_up_proof_id nullable=%q err=%v", nullable, err)
	}
	var checks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname IN (
		'billing_adjustment_requests_step_up_authority_615','billing_adjustment_decisions_step_up_authority_615')`).
		Scan(&checks); err != nil || checks != 2 {
		t.Fatalf("615 CHECK constraints = %d (%v), want 2", checks, err)
	}
	var rbacNone int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname LIKE 'custom_role_%_step_up_method_check'
		AND pg_get_constraintdef(oid) LIKE '%none%'`).Scan(&rbacNone); err != nil || rbacNone != 4 {
		t.Fatalf("custom RBAC step_up_method none constraints = %d (%v), want 4", rbacNone, err)
	}
	var waived bool
	if err := pool.QueryRow(ctx, `SELECT billing_adjustment_mfa_waived_615(gen_random_uuid(),gen_random_uuid(),
		gen_random_uuid(),'no-such-request','billing.adjustment.propose',gen_random_uuid(),'\x00'::bytea)`).
		Scan(&waived); err != nil || waived {
		t.Fatalf("waiver without audit = %v (%v), want false", waived, err)
	}
	var definition string
	if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_billing_adjustment_decision_100()'::regprocedure)`).
		Scan(&definition); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"control_platform_admin_435", "approved_step_up_waived", "billing_adjustment_mfa_waived_615"} {
		if !strings.Contains(definition, want) {
			t.Fatalf("decision trigger lacks %q", want)
		}
	}
}
