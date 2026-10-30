//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestCapabilityHoldPublished352: holds recorded before 352 read as refused
// publications (published false); a hold written with its publication says
// so; up, down and up again keep the existing holds.
func TestCapabilityHoldPublished352(t *testing.T) {
	const version = 352
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'352 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'hold-352','Hold 352','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	hold := `INSERT INTO edge_capability_publication_holds(scope_id,source_revision,actor_user_id,actor_scope_id,
		requested_node_ids,refused_node_ids,refused_at) VALUES($1,$2,$3,$1,ARRAY[$4::uuid],ARRAY[$4::uuid],now())`
	mustExec(t, pool, hold, scopeID, 1, userID, uuid.New())
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	mustExec(t, pool, hold, scopeID, 2, userID, uuid.New())
	mustExec(t, pool, `UPDATE edge_capability_publication_holds SET published=true WHERE scope_id=$1 AND source_revision=2`, scopeID)
	var refused, published int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE NOT published),count(*) FILTER (WHERE published)
		FROM edge_capability_publication_holds WHERE scope_id=$1`, scopeID).Scan(&refused, &published); err != nil ||
		refused != 1 || published != 1 {
		t.Fatalf("holds refused=%d published=%d (%v)", refused, published, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE edge_capability_publication_holds SET published=NULL WHERE scope_id=$1`,
		scopeID); sqlState(err) != "23502" {
		t.Fatalf("NULL published: %v, want 23502", err)
	}
}
