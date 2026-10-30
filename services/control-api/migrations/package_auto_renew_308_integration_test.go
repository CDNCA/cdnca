//go:build integration

package migrations_test

import (
	"testing"
)

// TestPackageAutoRenewMigration rolls 308 up, down and up on a 307 schema and
// checks the rollback refuses to drop an enabled switch.
func TestPackageAutoRenewMigration(t *testing.T) {
	const version = 308
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT
		has_table_privilege('cdnca_control_runtime','package_subscription_auto_renew_settings','UPDATE') AND
		has_table_privilege('cdnca_control_runtime','package_auto_renew_attempts','INSERT') AND
		NOT has_table_privilege('cdnca_control_app','package_auto_renew_attempts','UPDATE') AND
		(SELECT count(*) FROM notification_templates WHERE template_id LIKE 'package.auto_renew.%')=4 AND
		(SELECT count(*) FROM notification_event_policies WHERE event_type LIKE 'package.auto_renew.%' AND supported)=2`).
		Scan(&ready); err != nil || !ready {
		t.Fatalf("308 grants/seed = %v (%v)", ready, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO package_subscription_auto_renew_settings(
		subscription_id,tenant_scope_id,enabled,period,lead_hours,revision,updated_by_scope_id,
		updated_by_user_id,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),true,'month',72,1,
		gen_random_uuid(),gen_random_uuid(),now())`); err == nil {
		t.Fatal("setting for an unknown subscription was accepted")
	}
	// Disable the FK check only to plant an enabled switch for the rollback guard.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO package_subscription_auto_renew_settings(
		subscription_id,tenant_scope_id,enabled,period,lead_hours,revision,updated_by_scope_id,
		updated_by_user_id,updated_at) VALUES(gen_random_uuid(),gen_random_uuid(),true,'month',72,1,
		gen_random_uuid(),gen_random_uuid(),now())`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback dropped an enabled auto-renew switch")
	}
}
