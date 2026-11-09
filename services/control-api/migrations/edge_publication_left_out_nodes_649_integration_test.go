//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestEdgePublicationLeftOutNodes649UpDownUp rolls the
// two left-out node columns up, down and up again on the 648 head: both are
// uuid[] NOT NULL DEFAULT '{}' and refuse a NULL element; down removes them.
func TestEdgePublicationLeftOutNodes649UpDownUp(t *testing.T) {
	const version = 649
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	columns := func() map[string]string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT column_name, udt_name || ' ' || is_nullable || ' ' || COALESCE(column_default,'')
			FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='edge_config_publications'
			  AND column_name IN ('key_envelope_oversized_node_ids','site_selection_unsupported_node_ids')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		found := map[string]string{}
		for rows.Next() {
			var name, shape string
			if err := rows.Scan(&name, &shape); err != nil {
				t.Fatal(err)
			}
			found[name] = shape
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return found
	}
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		got := columns()
		if !step.present {
			if len(got) != 0 {
				t.Fatalf("after down the columns remain: %v", got)
			}
			continue
		}
		for _, name := range []string{"key_envelope_oversized_node_ids", "site_selection_unsupported_node_ids"} {
			if got[name] != "_uuid NO '{}'::uuid[]" {
				t.Fatalf("after %s %s = %q, want uuid[] NOT NULL DEFAULT '{}'", step.direction, name, got[name])
			}
		}
	}
	for _, check := range []string{
		"edge_config_publications_key_envelope_oversized_649_check",
		"edge_config_publications_site_selection_unsupported_649_check",
	} {
		var definition string
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conname=$1 AND conrelid=(current_schema() || '.edge_config_publications')::regclass`, check).Scan(&definition); err != nil {
			t.Fatalf("%s: %v", check, err)
		}
		for _, want := range []string{"cardinality", "10000", "array_position"} {
			if !strings.Contains(definition, want) {
				t.Fatalf("%s = %s lacks %q", check, definition, want)
			}
		}
	}
}
