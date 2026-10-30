//go:build integration

package migrations_test

import (
	"slices"
	"testing"
)

// TestDomainEventOutbox368DownRestoresDeploymentOutboxShape: 368 down
// recreates the deployment outbox and fanout receipts dropped by 368 up; the
// recreated tables must carry the constraints, foreign key actions and
// triggers (and trigger function bodies) they had at the 367 head (after 284 node purge and 289 agent
// queue), or 289/284 down fail on names that no longer exist.
func TestDomainEventOutbox368DownRestoresDeploymentOutboxShape(t *testing.T) {
	const version = 368
	pool := migrationPoolAt(t, version-1)
	shape := func() []string {
		rows, err := pool.Query(t.Context(), `
			SELECT 'constraint '||conrelid::regclass::text||' '||conname||' '||pg_get_constraintdef(oid)
			FROM pg_constraint
			WHERE conrelid IN ('deployment_domain_event_source_outbox'::regclass,
				'deployment_domain_event_fanout_receipts'::regclass)
			UNION ALL
			SELECT 'trigger '||tgrelid::regclass::text||' '||tgname||' '||pg_get_triggerdef(oid)
			FROM pg_trigger
			WHERE NOT tgisinternal AND tgrelid IN ('deployment_domain_event_source_outbox'::regclass,
				'deployment_domain_event_fanout_receipts'::regclass)
			UNION ALL
			SELECT 'index '||indexrelid::regclass::text||' '||pg_get_indexdef(indexrelid)
			FROM pg_index
			WHERE indrelid IN ('deployment_domain_event_source_outbox'::regclass,
				'deployment_domain_event_fanout_receipts'::regclass)
			UNION ALL
			SELECT 'function '||pg_get_functiondef(oid)
			FROM pg_proc
			WHERE proname IN ('validate_deployment_domain_event_source_outbox',
				'validate_deployment_domain_event_fanout_receipt_189')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var result []string
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			result = append(result, line)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		slices.Sort(result)
		return result
	}
	before := shape()
	for _, step := range []string{"up", "down"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	after := shape()
	for _, line := range before {
		if !slices.Contains(after, line) {
			t.Errorf("lost after 368 down: %s", line)
		}
	}
	for _, line := range after {
		if !slices.Contains(before, line) {
			t.Errorf("new after 368 down: %s", line)
		}
	}
}
