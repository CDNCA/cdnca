package migrations

import (
	"strings"
	"testing"
)

// Migration 644 (predecessor 643_probe_dnspup_followup): this controller's
// local stop list of plugin feature codes (module.*, pack.*, theme.*) and the
// Idempotency-Key receipts of its two writes. Up only adds tables; down drops
// them. A row takes the code out of the lease's grant on this controller
// (entitlementguard); the licence and the lease are untouched.
func TestPluginLocalDisables644Contract(t *testing.T) {
	read := func(direction string) string {
		body, err := FS.ReadFile("644_plugin_local_disables." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("up"), read("down")
	tables := []string{"plugin_local_disables", "plugin_local_disable_requests"}
	for _, fragment := range []string{
		"ERRCODE='P6440'", "(SELECT count(*) FROM schema_migrations) <> 643",
		"(SELECT max(version) FROM schema_migrations) <> 643",
		"plugin_id text PRIMARY KEY", "feature_code text NOT NULL UNIQUE",
		"feature_code ~ '^(module|pack|theme)\\.[a-z][a-z0-9_-]*(\\.[a-z][a-z0-9_-]*)*$'",
		"char_length(reason) BETWEEN 1 AND 500",
		"operation IN ('disable', 'enable')",
		"PRIMARY KEY (actor_user_id, idempotency_key)",
		"REVOKE ALL ON " + strings.Join(tables, ", ") + " FROM PUBLIC",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON " + strings.Join(tables, ", ") + " TO cdnca_control_app, cdnca_control_runtime",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("644 up missing %q", fragment)
		}
	}
	for _, table := range tables {
		if !strings.Contains(up, "CREATE TABLE "+table+" (") || !strings.Contains(down, "DROP TABLE "+table+";") {
			t.Errorf("644 must create and drop %s", table)
		}
	}
	for _, fragment := range []string{"ERRCODE='P6441'", "migration_id='644_plugin_local_disables'"} {
		if !strings.Contains(down, fragment) {
			t.Errorf("644 down missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE ", "ALTER TABLE"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("644 up must not contain %q", forbidden)
		}
	}
}
