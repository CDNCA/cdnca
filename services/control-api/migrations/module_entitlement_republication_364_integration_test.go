//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestModuleEntitlementRepublicationMigration rolls 364 up, down and up on a
// 363 schema; the up then accepts trigger and source kind module_entitlement,
// and a hold blocks the rollback.
func TestModuleEntitlementRepublicationMigration(t *testing.T) {
	const version = 364
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var accepts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE pg_get_constraintdef(oid) LIKE '%module_entitlement%'
		AND conname IN ('edge_system_revision_segments_source_check','edge_system_republication_heads_triggers_check',
		  'edge_automatic_publication_requests_source_kind_check','edge_automatic_publication_requests_check',
		  'edge_automatic_publication_l4_intent_presence_092')`).Scan(&accepts); err != nil || accepts != 5 {
		t.Fatalf("constraints accepting module_entitlement = %d err=%v", accepts, err)
	}
	scope := uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope)
	if _, err := pool.Exec(ctx, `INSERT INTO edge_module_publication_holds(scope_id,module_code,source_revision,held_at)
		VALUES($1,'Module.bad',1,now())`, scope); err == nil {
		t.Fatal("invalid module code accepted")
	}
	mustExec(t, pool, `INSERT INTO edge_module_publication_holds(scope_id,module_code,source_revision,held_at)
		VALUES($1,'pack.crs',1,now())`, scope)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback with a hold accepted")
	}
}
