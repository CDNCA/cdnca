//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestNodeTelemetryHealth592: up/down/up round trip; the four nullable
// telemetry_* columns and the all-or-none shape check.
func TestNodeTelemetryHealth592(t *testing.T) {
	pool := migrationPoolAt(t, 592-1) // the predecessor head (renumbered with 592)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, 592); err != nil {
			t.Fatalf("%s 592: %v", step, err)
		}
	}
	for _, column := range []string{"telemetry_error_code", "telemetry_first_seen_at", "telemetry_last_seen_at", "telemetry_count"} {
		var nullable string
		if err := pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name=$1`, column).Scan(&nullable); err != nil {
			t.Fatalf("%s: %v", column, err)
		}
		if nullable != "YES" {
			t.Fatalf("%s nullable = %s", column, nullable)
		}
	}
	var definition string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='node_presence_telemetry_592_shape_check'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"telemetry_error_code IS NULL", "telemetry_first_seen_at <= telemetry_last_seen_at"} {
		if !strings.Contains(definition, want) {
			t.Fatalf("shape check = %s lacks %s", definition, want)
		}
	}
}
