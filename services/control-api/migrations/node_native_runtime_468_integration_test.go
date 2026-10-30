//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestNodeNativeRuntime468: up/down/up round trip; the four nullable
// native_runtime_* columns and their checks.
func TestNodeNativeRuntime468(t *testing.T) {
	pool := migrationPoolAt(t, 467)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, 468); err != nil {
			t.Fatalf("%s 468: %v", step, err)
		}
	}
	for _, column := range []string{"native_runtime_state", "native_runtime_release", "native_runtime_previous_release", "native_runtime_error_code"} {
		var nullable string
		if err := pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name=$1`, column).Scan(&nullable); err != nil {
			t.Fatalf("%s: %v", column, err)
		}
		if nullable != "YES" {
			t.Fatalf("%s nullable = %s", column, nullable)
		}
	}
	for name, wants := range map[string][]string{
		"node_presence_native_runtime_state_468_check": {"'switched'", "'unchanged'", "'rolled_back'"},
		"node_presence_native_runtime_468_shape_check": {"native_runtime_error_code IS NULL", "'rolled_back'"},
	} {
		var definition string
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1`, name).Scan(&definition); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, want := range wants {
			if !strings.Contains(definition, want) {
				t.Fatalf("%s = %s lacks %s", name, definition, want)
			}
		}
	}
}
