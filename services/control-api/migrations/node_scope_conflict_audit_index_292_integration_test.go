//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestNodeScopeConflictAuditIndexMigration rolls the refusal index up, down
// and up again on a 291 schema.
func TestNodeScopeConflictAuditIndexMigration(t *testing.T) {
	const version = 292
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var definition string
	if err := pool.QueryRow(ctx, `SELECT pg_get_indexdef('audit_events_node_scope_conflict_292_idx'::regclass)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"(resource_id, occurred_at DESC)", "edge_publication.node_scope_conflict", "'node'"} {
		if !strings.Contains(definition, want) {
			t.Fatalf("index %s lacks %q", definition, want)
		}
	}
}
