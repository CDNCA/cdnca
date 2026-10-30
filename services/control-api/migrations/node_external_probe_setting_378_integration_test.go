//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestNodeExternalProbeSetting378: existing and new nodes get
// external_probe=true; a non-boolean value is refused; up, down, up.
func TestNodeExternalProbeSetting378(t *testing.T) {
	const version = 378
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	scopeID, userID, existing := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'probe-378','P','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'old','active',$3,1)`,
		existing, scopeID, userID)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	fresh := uuid.New()
	mustExec(t, pool, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'new','active',$3,2)`,
		fresh, scopeID, userID)
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE id IN ($1,$2)
		AND management_settings->'external_probe'='true'::jsonb`, existing, fresh).Scan(&count); err != nil || count != 2 {
		t.Fatalf("external_probe defaults: %d %v", count, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE nodes SET management_settings=jsonb_set(management_settings,'{external_probe}','"yes"')
		WHERE id=$1`, existing); sqlState(err) != "23514" {
		t.Fatalf("non-boolean external_probe: %v", err)
	}
}
