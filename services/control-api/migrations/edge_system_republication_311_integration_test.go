//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestEdgeSystemRepublicationMigration rolls 311 up, down and up, checks the
// head's trigger and lease constraints and that rollback refuses to orphan a
// recorded system revision segment.
func TestEdgeSystemRepublicationMigration(t *testing.T) {
	const version = 311
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	tenantID, scopeID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'syspub')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_system_republication_heads(
		scope_id,generation,state,triggers,due_at,attempt,created_at,updated_at)
		VALUES($1,1,'pending',ARRAY['unknown'],now(),0,now(),now())`, scopeID); err == nil {
		t.Fatal("unknown trigger accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_system_republication_heads(
		scope_id,generation,state,triggers,due_at,attempt,created_at,updated_at)
		VALUES($1,1,'leased',ARRAY['node_capability'],now(),0,now(),now())`, scopeID); err == nil {
		t.Fatal("leased head without a lease accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_system_republication_heads(
		scope_id,generation,state,triggers,due_at,attempt,created_at,updated_at)
		VALUES($1,1,'pending',ARRAY['node_capability','line_group'],now(),0,now(),now())`, scopeID); err != nil {
		t.Fatalf("pending head rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
		VALUES($1,3,3,'line_group',now())`, scopeID); err == nil {
		t.Fatal("empty revision segment accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
		VALUES($1,3,4,'line_group',now())`, scopeID); err != nil {
		t.Fatalf("revision segment rejected: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback orphaned system republication facts")
	}
}
