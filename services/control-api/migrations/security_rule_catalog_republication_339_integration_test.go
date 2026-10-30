//go:build integration

package migrations_test

import "testing"

// TestSecurityRuleCatalogRepublicationMigration rolls 339 up, down and up on
// a 338 schema next to a sibling schema that already has the guarded
// constraints; the up then accepts trigger and source kind rule_catalog.
func TestSecurityRuleCatalogRepublicationMigration(t *testing.T) {
	const version = 339
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	seedSiblingSchemaConstraints(t, pool, "edge_system_republication_heads_triggers_check",
		"edge_system_republication_attempts_triggers_check", "edge_system_revision_segments_source_check",
		"edge_automatic_publication_requests_source_kind_check", "edge_automatic_publication_requests_operation_check",
		"edge_automatic_publication_requests_reason_check", "edge_automatic_publication_requests_check",
		"edge_automatic_publication_l4_intent_presence_092")
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var accepts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE connamespace=current_schema()::regnamespace
		AND pg_get_constraintdef(oid) LIKE '%rule_catalog%'
		AND conname IN ('edge_system_revision_segments_source_check','edge_system_republication_heads_triggers_check',
		  'edge_automatic_publication_requests_source_kind_check','edge_automatic_publication_requests_check',
		  'edge_automatic_publication_l4_intent_presence_092')`).Scan(&accepts); err != nil || accepts != 5 {
		t.Fatalf("constraints accepting rule_catalog = %d err=%v", accepts, err)
	}
}
