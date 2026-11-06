package migrations

import (
	"strings"
	"testing"
)

// Migration 642 (predecessor 641_market_node_settings):
// the buyer's own alias and note for a market supply and a subscribed node,
// kept on this controller only. Columns only, no data change.
func TestMarketLocalLabels642Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"642_market_local_labels.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 641", "(SELECT max(version) FROM schema_migrations) <> 641",
			"migration_id='641_market_node_settings'", "ERRCODE='P6420'",
			"ALTER TABLE site_supplies\n    ADD COLUMN local_alias text NOT NULL DEFAULT ''",
			"ALTER TABLE market_subscribed_nodes\n    ADD COLUMN local_alias text NOT NULL DEFAULT ''",
			"char_length(local_alias) <= 64", "char_length(local_note) <= 500",
			"kind = 'market_subscription' OR (local_alias = '' AND local_note = '')",
		}, []string{"DELETE FROM", "UPDATE ", "DROP "}},
		{"642_market_local_labels.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 642", "migration_id='642_market_local_labels'",
			"ERRCODE='P6421'", "DROP COLUMN local_note, DROP COLUMN local_alias",
		}, []string{"DELETE FROM", "UPDATE "}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
}
