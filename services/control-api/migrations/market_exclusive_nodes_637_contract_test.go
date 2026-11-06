package migrations

import (
	"strings"
	"testing"
)

// Migration 637 (predecessor
// 636_plugin_installation_platform_targets): the buyer marks exclusive
// subscribed nodes and keeps their relayed host metrics for a day. Up only
// adds; down drops both.
func TestMarketExclusiveNodes637Contract(t *testing.T) {
	read := func(direction string) string {
		body, err := FS.ReadFile("637_market_exclusive_nodes." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("up"), read("down")
	for _, fragment := range []string{
		"ERRCODE='P6370'", "migration_id='636_plugin_installation_platform_targets'",
		"ALTER TABLE market_subscribed_nodes ADD COLUMN exclusive boolean NOT NULL DEFAULT false",
		"CREATE TABLE market_subscribed_node_host_samples", "PRIMARY KEY (leaf_member_id, ref, minute)",
		"CHECK (minute = date_trunc('minute', minute))",
		"REVOKE ALL ON market_subscribed_node_host_samples FROM PUBLIC",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("637 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{"ERRCODE='P6371'", "migration_id='637_market_exclusive_nodes'",
		"DROP TABLE market_subscribed_node_host_samples", "ALTER TABLE market_subscribed_nodes DROP COLUMN exclusive"} {
		if !strings.Contains(down, fragment) {
			t.Errorf("637 down missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE market_subscribed_nodes"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("637 up must not contain %q", forbidden)
		}
	}
}
