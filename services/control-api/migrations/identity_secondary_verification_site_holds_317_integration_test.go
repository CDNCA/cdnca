//go:build integration

package migrations_test

import "testing"

// TestIdentitySecondaryVerificationSiteHoldsMigration rolls 317 up, down and up
// on a 316 schema.
func TestIdentitySecondaryVerificationSiteHoldsMigration(t *testing.T) {
	const version = 317
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_runtime','identity_secondary_verification_site_holds','UPDATE') AND
		NOT has_table_privilege('cdnca_control_app','identity_secondary_verification_site_holds','DELETE')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants=%v err=%v", granted, err)
	}
}
