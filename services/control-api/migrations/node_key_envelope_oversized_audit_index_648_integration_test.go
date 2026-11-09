//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestNodeKeyEnvelopeOversizedAuditIndex648UpDownUp rolls
// the "旧配置仍生效" lookup index up, down and up again on the 647 head; down
// leaves no index behind.
func TestNodeKeyEnvelopeOversizedAuditIndex648UpDownUp(t *testing.T) {
	const version = 648
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	indexed := func() bool {
		t.Helper()
		var present bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema() || '.audit_events_node_key_envelope_oversized_648_idx') IS NOT NULL`).Scan(&present); err != nil {
			t.Fatal(err)
		}
		return present
	}
	head := func() int64 {
		t.Helper()
		var current int64
		if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&current); err != nil {
			t.Fatal(err)
		}
		return current
	}
	for _, step := range []struct {
		direction string
		head      int64
		indexed   bool
	}{{"up", version, true}, {"down", version - 1, false}, {"up", version, true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := head(); got != step.head || indexed() != step.indexed {
			t.Fatalf("after %s: head %d indexed %v, want %d %v", step.direction, got, indexed(), step.head, step.indexed)
		}
	}
	var definition string
	if err := pool.QueryRow(ctx, `SELECT pg_get_indexdef((current_schema() || '.audit_events_node_key_envelope_oversized_648_idx')::regclass)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(resource_id, scope_id, occurred_at DESC, stream_position DESC)",
		"'edge_publication.key_envelope_oversized'", "'node'",
	} {
		if !strings.Contains(definition, want) {
			t.Fatalf("index %s lacks %q", definition, want)
		}
	}
}
