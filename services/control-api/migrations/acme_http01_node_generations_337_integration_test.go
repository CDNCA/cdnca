//go:build integration

package migrations_test

import "testing"

// TestACMEHTTP01NodeGenerationsMigration rolls 337 up, down and up on an empty
// schema; the node overlay tables only exist while it is applied.
func TestACMEHTTP01NodeGenerationsMigration(t *testing.T) {
	const version = 337
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var tables int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM unnest(ARRAY[
			'acme_http01_node_challenges','acme_http01_node_challenge_targets',
			'acme_http01_node_overlay_generations','acme_http01_node_overlay_generation_tokens',
			'acme_http01_node_overlay_states','acme_http01_node_overlay_deliveries']) name
			WHERE to_regclass(current_schema()||'.'||name) IS NOT NULL`).Scan(&tables); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 6, false: 0}[step == "up"]; tables != want {
			t.Fatalf("after %s: %d tables", step, tables)
		}
	}
}
