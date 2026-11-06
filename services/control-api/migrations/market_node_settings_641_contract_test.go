package migrations

import (
	"strings"
	"testing"
)

// Migration 641 (predecessor
// 640_line_group_dnshub_batch_idempotency): the leaf's record of a dedicated
// subscriber's node settings (snapshot, its forwards, the operator's
// disables) and the subscriber's own document and deliveries. Up only adds
// tables; down drops them.
func TestMarketNodeSettings641Contract(t *testing.T) {
	read := func(direction string) string {
		body, err := FS.ReadFile("641_market_node_settings." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("up"), read("down")
	tables := []string{"market_supply_node_settings", "market_supply_node_streams", "market_supply_node_disables",
		"market_node_settings", "market_node_settings_deliveries"}
	for _, fragment := range []string{
		"ERRCODE='P6410'", "migration_id='640_line_group_dnshub_batch_idempotency'",
		"(SELECT count(*) FROM schema_migrations) <> 640",
		"kind IN ('stream', 'rule')", "removed_reason IN ('subscription_ended', 'supply_paused')",
		"stream_id uuid NOT NULL UNIQUE",
		"REVOKE ALL ON " + strings.Join(tables, ", ") + " FROM PUBLIC",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("641 up missing %q", fragment)
		}
	}
	for _, table := range tables {
		if !strings.Contains(up, "CREATE TABLE "+table+" (") || !strings.Contains(down, "DROP TABLE "+table+";") {
			t.Errorf("641 must create and drop %s", table)
		}
	}
	for _, fragment := range []string{"ERRCODE='P6411'", "migration_id='641_market_node_settings'"} {
		if !strings.Contains(down, fragment) {
			t.Errorf("641 down missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE ", "ALTER TABLE"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("641 up must not contain %q", forbidden)
		}
	}
}
