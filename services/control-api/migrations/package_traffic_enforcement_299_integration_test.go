//go:build integration

package migrations_test

import "testing"

// TestPackageTrafficEnforcementMigration rolls 299 up, down and up on a 298
// schema and checks the runtime grants and the close-once suspension fact.
func TestPackageTrafficEnforcementMigration(t *testing.T) {
	const version = 299
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT
		has_table_privilege('cdnca_control_app','package_traffic_site_suspensions','INSERT') AND
		has_table_privilege('cdnca_control_runtime','package_traffic_enforcement_schedule','UPDATE') AND
		NOT has_table_privilege('cdnca_control_app','package_traffic_site_suspensions','DELETE') AND
		(SELECT count(*) FROM notification_templates WHERE template_id IN
		 ('package.traffic.suspended.zh-cn','package.traffic.recovered.zh-cn'))=4`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants and templates = %v (%v)", granted, err)
	}
}
