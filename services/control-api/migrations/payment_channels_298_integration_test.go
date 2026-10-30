//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestPaymentChannelsMigration rolls 298 up, down and up on a 297 schema and
// checks the rollback refuses to discard configured channels.
func TestPaymentChannelsMigration(t *testing.T) {
	const version = 298
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_app','payment_channels','INSERT') AND
		has_table_privilege('cdnca_control_runtime','payment_channel_reconcile_schedule','UPDATE') AND
		NOT has_table_privilege('cdnca_control_app','payment_channels','DELETE')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("runtime grants = %v (%v)", granted, err)
	}
	user := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO payment_channels(id,provider,method,display_name,enabled,created_by,updated_by,
		created_at,updated_at) VALUES($1,'epay','alipay','x',true,$2,$2,now(),now())`, uuid.New(), user); err == nil {
		t.Fatal("enabled epay without risk acknowledgement and secrets was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO payment_channels(id,provider,method,display_name,created_by,updated_by,
		created_at,updated_at) VALUES($1,'epay','alipay','draft',$2,$2,now(),now())`, uuid.New(), user); err != nil {
		t.Fatalf("disabled draft: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback discarded a configured channel")
	}
}
