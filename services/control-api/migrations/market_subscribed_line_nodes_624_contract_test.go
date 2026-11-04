package migrations

import (
	"strings"
	"testing"
)

// Migration 624 (on top of 623):
// subscribed market nodes join line groups like own nodes. The serving view
// keeps its columns and only adds the market conditions; the down script
// refuses while a live line group still carries a subscribed node.
func TestMarketSubscribedLineNodes624Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"624_market_subscribed_line_nodes.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 623", "(SELECT max(version) FROM schema_migrations) <> 623",
			"migration_id='623_market_supply_local_disable'", "ERRCODE='P6240'",
			"CREATE TABLE market_subscribed_nodes (", "UNIQUE (market_subscription_id, ref)",
			"ADD COLUMN market_node_id uuid", "CHECK (market_node_id IS NULL OR node_id IS NULL)",
			"CREATE OR REPLACE VIEW node_line_endpoint_serving AS",
			"market.removed_at IS NULL AND market.available",
			"supply.status = 'active' AND supply.local_disabled_at IS NULL",
			"COALESCE(market.health = 'unhealthy', false)) AS held",
			"SELECT tenant_scope_id, line_group_id, config_revision, endpoint_id, node_id, address, address_family,\n       admin_enabled, held,",
			"CREATE TABLE site_market_line_rollouts (",
			"CREATE FUNCTION market_line_endpoint_unserved(", "AND leaf.applied_revision > 0))",
		}, []string{"DELETE FROM", "UPDATE ", "DROP "}},
		{"624_market_subscribed_line_nodes.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 624", "migration_id='624_market_subscribed_line_nodes'",
			"ERRCODE='P6241'", "ERRCODE='P6242'", "WHERE endpoint.market_node_id IS NOT NULL",
			"CREATE OR REPLACE VIEW node_line_endpoint_serving AS",
			"DROP COLUMN market_node_id", "DROP TABLE market_subscribed_nodes", "DROP TABLE site_market_line_rollouts",
			"DROP FUNCTION market_line_endpoint_unserved(uuid, uuid, uuid, bigint, uuid)",
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
