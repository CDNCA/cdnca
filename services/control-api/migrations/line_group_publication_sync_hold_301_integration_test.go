//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestLineGroupPublicationSyncHoldMigration rolls 301 up, down and up and
// checks the new hold source and that rollback refuses to orphan its facts.
func TestLineGroupPublicationSyncHoldMigration(t *testing.T) {
	const version = 301
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'sync-hold','Sync hold','test-only')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'sync-hold','active',$3,1)`,
			[]any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,changed_at,updated_at)
		VALUES($1,'config_sync',true,'sync_failed',1,now(),now(),now())`, nodeID); err != nil {
		t.Fatalf("config_sync hold rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,changed_at,updated_at)
		VALUES($1,'other_source',false,'x',1,now(),now())`, nodeID); err == nil {
		t.Fatal("unknown hold source accepted")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback orphaned a config_sync hold")
	}
}
