//go:build integration

package migrations_test

import "testing"

// TestChallengePolicyRedeliveryMigration rolls 343 up, down and up on a 342
// schema; the up then accepts trigger and source kind challenge_delivery and
// holds the redelivery table.
func TestChallengePolicyRedeliveryMigration(t *testing.T) {
	const version = 343
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	// 同库另一 schema 带同名约束时，守卫只数当前 schema（否则 P3430）。
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE connamespace=current_schema()::regnamespace AND pg_get_constraintdef(oid) LIKE '%challenge_deliver%'
		AND conname IN ('edge_system_revision_segments_source_check','edge_system_republication_heads_triggers_check',
		  'edge_automatic_publication_requests_source_kind_check','edge_automatic_publication_requests_operation_check',
		  'edge_automatic_publication_requests_reason_check','edge_automatic_publication_requests_check',
		  'edge_automatic_publication_l4_intent_presence_092')`).Scan(&accepts); err != nil || accepts != 7 {
		t.Fatalf("constraints accepting challenge_delivery = %d err=%v", accepts, err)
	}
	var table bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('edge_challenge_redeliveries') IS NOT NULL`).Scan(&table); err != nil || !table {
		t.Fatalf("edge_challenge_redeliveries missing: %v", err)
	}
}
