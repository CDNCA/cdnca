//go:build integration

package migrations_test

import "testing"

// TestIPIntelLibraryMigration rolls 315 up, down and up on a 314 schema and
// checks the runtime grants and the forward-only trigger.
func TestIPIntelLibraryMigration(t *testing.T) {
	const version = 315
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_runtime','ip_intel_library','UPDATE') AND
		has_table_privilege('cdnca_control_runtime','ip_intel_sync_state','UPDATE') AND
		NOT has_table_privilege('cdnca_control_app','ip_intel_library','DELETE')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("grants=%v err=%v", granted, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO ip_intel_library(revision,artifact_sha256,artifact_bytes,artifact,signed_release,
		key_id,capability_version,data_updated_at,applied_at)
		VALUES(2,repeat('a',64),65,decode(repeat('00',65),'hex'),'{}','k',2,now(),now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE ip_intel_library SET revision=1`); err == nil {
		t.Fatal("library moved backwards")
	}
}
