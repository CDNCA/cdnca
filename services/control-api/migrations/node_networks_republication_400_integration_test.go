//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestNodeNetworksRepublication400: the checks take trigger node_networks
// (system channel and automatic requests), up/down/up round trips, and down
// refuses while a node_networks fact exists. The version is the embedded
// placeholder's (renumbered on merge).
func TestNodeNetworksRepublication400(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_node_networks_republication.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("node networks migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	scopeID := uuid.New()
	mustExec(t, pool, `SET session_replication_role = replica`)
	mustExec(t, pool, `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
		VALUES($1,1,2,'node_networks',now())`, scopeID)
	if _, err := pool.Exec(ctx, `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
		VALUES($1,2,3,'node_addresses',now())`, scopeID); sqlState(err) != "23514" {
		t.Fatalf("unknown source: %v, want 23514", err)
	}
	mustExec(t, pool, `SET session_replication_role = origin`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4002" {
		t.Fatalf("down with a node_networks segment: %v, want P4002", err)
	}
	mustExec(t, pool, `DELETE FROM edge_system_revision_segments WHERE scope_id=$1`, scopeID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down without node_networks facts: %v", err)
	}
}
