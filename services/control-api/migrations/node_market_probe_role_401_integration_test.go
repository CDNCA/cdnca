//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestNodeMarketProbeRole401: up/down/up round trip; the nullable role column
// accepts only the three roles.
func TestNodeMarketProbeRole401(t *testing.T) {
	pool := migrationPoolAt(t, 397)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, 401); err != nil {
			t.Fatalf("%s 401: %v", step, err)
		}
	}
	var nullable, constraint string
	if err := pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='node_presence' AND column_name='market_probe_role'`).Scan(&nullable); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname='node_presence_market_probe_role_401_check'`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	if nullable != "YES" {
		t.Fatalf("market_probe_role nullable = %s", nullable)
	}
	for _, role := range []string{"'probe_only'", "'join_market'", "'disabled'"} {
		if !strings.Contains(constraint, role) {
			t.Fatalf("constraint %s lacks %s", constraint, role)
		}
	}
}
