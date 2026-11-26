//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestActiveConfigIdentityRollbackFailedServing687: up lets the identity
// validator's no-deployment branch take a rollback_failed apply, down
// restores the 232 states, up again applies.
func TestActiveConfigIdentityRollbackFailedServing687(t *testing.T) {
	const version = 687
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	source := func() string {
		t.Helper()
		var text string
		if err := pool.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid =
			to_regprocedure('active_config_identity_artifact_valid_087(uuid,uuid,bytea,uuid,integer,text)')`).Scan(&text); err != nil {
			t.Fatal(err)
		}
		return text
	}
	const relaxed = "deployment.state IN ('activated', 'healthy', 'rollback_failed')"
	if strings.Contains(source(), relaxed) {
		t.Fatal("686 validator already takes rollback_failed")
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if !strings.Contains(source(), relaxed) {
		t.Fatal("687 validator does not take rollback_failed")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if strings.Contains(source(), relaxed) || !strings.Contains(source(), "deployment.state IN ('activated', 'healthy')") {
		t.Fatal("687 down did not restore the 232 validator")
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("second up %d: %v", version, err)
	}
}
