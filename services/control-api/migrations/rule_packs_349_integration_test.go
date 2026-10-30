//go:build integration

package migrations_test

import "testing"

// TestRulePacksMigration rolls 349 up, down and up: the rule pack tables
// exist only while it is applied.
func TestRulePacksMigration(t *testing.T) {
	const version = 349
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var tables int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_tables WHERE schemaname=current_schema() AND
			tablename IN ('rule_packs','rule_pack_artifacts','rule_pack_enablements','site_security_mounts',
			'rule_pack_site_mount_artifacts')`).Scan(&tables); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 5, false: 0}[step == "up"]; tables != want {
			t.Fatalf("after %s: %d tables", step, tables)
		}
	}
}
