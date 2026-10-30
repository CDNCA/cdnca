//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestPackageAutomaticPublication457 rolls 457 up, down and up: an automatic
// policy without nodes or snapshot is accepted only with 457, and down
// refuses (P4572) once such a policy exists.
func TestPackageAutomaticPublication457(t *testing.T) {
	const version = 457
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenant, scope, user := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'autopub 457')`, tenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'autopub','hash')`,
		user, "autopub-457-"+user.String())
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, user)
	insert := func(revision int) error {
		_, err := pool.Exec(ctx, `INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,
			activation_timeout_ms,observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,
			actor_scope_id,actor_user_id,reason,created_at)
			VALUES($1,$2,'automatic','{}',60000,30000,3,3,1800,$1,$3,'package_opened',clock_timestamp())`, scope, revision, user)
		return err
	}
	if err := insert(1); err == nil {
		t.Fatal("086 accepted an automatic policy without nodes")
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	if err := insert(1); err != nil {
		t.Fatalf("automatic policy without nodes after 457: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4572" {
		t.Fatalf("down with a policy without nodes: %v, want P4572", err)
	}
}
