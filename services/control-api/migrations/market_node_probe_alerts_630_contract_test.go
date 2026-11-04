package migrations

import (
	"strings"
	"testing"
)

// Migration 630 (on top of 629
// market_supply_l2_config): subscribed market nodes carry this
// controller's probe alert state, and market.node.probe_unreachable /
// probe_recovered notify the purchasers; templates never carry the node
// address. Down refuses while such notifications exist.
func TestMarketNodeProbeAlerts630Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"630_market_node_probe_alerts.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 629", "(SELECT max(version) FROM schema_migrations) <> 629",
			"migration_id='629_market_supply_l2_config'", "ERRCODE='P6300'",
			"ADD COLUMN probe_alerted boolean NOT NULL DEFAULT false",
			"ADD COLUMN probe_alert_revision bigint NOT NULL DEFAULT 0",
			"('market.node.probe_unreachable', true, true, true, 1, 1, true, true, false, now())",
			"('market.node.probe_recovered', true, true, true, 1, 1, true, true, false, now())",
			"ARRAY['node','seller','supply','market_health','occurred_at']",
		}, []string{"DELETE FROM", "UPDATE ", "DROP TABLE", "{{.address", "{{.ip", "{{.node_ip"}},
		{"630_market_node_probe_alerts.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 630", "migration_id='630_market_node_probe_alerts'",
			"ERRCODE='P6301'", "ERRCODE='P6302'", "FROM notification_outbox WHERE template_id IN",
			"DROP COLUMN probe_alert_revision, DROP COLUMN probe_alerted",
		}, []string{"DROP TABLE"}},
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
