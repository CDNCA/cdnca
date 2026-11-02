//go:build integration

package migrations_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestNodePurgeFKRestore616: at 615 thirteen keys reachable from nodes restrict
// the delete beyond the intended ones; after 616 only l2_topology_nodes (284)
// and the eight ACME HTTP-01 tables (346 purges them explicitly) still
// restrict; the guard refuses a second apply; down restores the restricts and
// 615→616 goes up, down and up again.
func TestNodePurgeFKRestore616(t *testing.T) {
	const version = 616
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	restricted := func() []string {
		t.Helper()
		rows, err := pool.Query(ctx, `
			WITH RECURSIVE reach(relation) AS (
				SELECT (current_schema()||'.nodes')::regclass::oid
				UNION
				SELECT c.conrelid FROM pg_constraint c JOIN reach ON c.confrelid=reach.relation
				WHERE c.contype='f' AND c.confdeltype='c'
			)
			SELECT DISTINCT c.conrelid::regclass::text||'.'||c.conname FROM pg_constraint c
			JOIN reach ON c.confrelid=reach.relation
			WHERE c.contype='f' AND c.confdeltype IN ('r','a')`)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(keys)
		return keys
	}
	intended := []string{
		"acme_http01_node_challenge_targets.acme_http01_node_challenge_targets_node_id_fkey",
		"acme_http01_node_overlay_cleanup_debts.acme_http01_node_overlay_cleanup_debts_node_id_fkey",
		"acme_http01_node_overlay_generation_coverages.acme_http01_node_overlay_generation_coverages_node_id_fkey",
		"acme_http01_node_overlay_generations.acme_http01_node_overlay_generations_node_id_fkey",
		"acme_http01_node_overlay_states.acme_http01_node_overlay_states_node_id_fkey",
		"acme_http01_overlay_backfill_nodes.acme_http01_overlay_backfill_nodes_node_id_fkey",
		"acme_http01_overlay_backfill_quarantines.acme_http01_overlay_backfill_quarantines_node_id_fkey",
		"acme_http01_site_overlay_epoch_members.acme_http01_site_overlay_epoch_members_node_id_fkey",
		"l2_topology_nodes.l2_topology_nodes_tenant_scope_id_node_id_fkey",
	}
	before := restricted()
	if len(before) != len(intended)+13 {
		t.Fatalf("615 restricting keys = %d %v, want %d", len(before), before, len(intended)+13)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if after := restricted(); strings.Join(after, ",") != strings.Join(intended, ",") {
		t.Fatalf("616 restricting keys = %v, want %v", after, intended)
	}
	up, err := controlmigrations.FS.ReadFile("616_node_purge_fk_restore.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(up)); err == nil || !strings.Contains(err.Error(), "P6160") {
		t.Fatalf("616 re-applied on the head: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if again := restricted(); strings.Join(again, ",") != strings.Join(before, ",") {
		t.Fatalf("616 down restricting keys = %v, want %v", again, before)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up again %d: %v", version, err)
	}
}
