package migrations

import (
	"strings"
	"testing"
)

// Migration 629 (on top of 628
// global_firewall_redelivery): a market supply line group may name any live
// L2 configuration of its scope (supply groups have no region); ordinary line
// groups keep the 504 region rule. Down restores the 504 bodies and refuses
// while a supply group names a configuration of another region.
func TestMarketSupplyL2Config629Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"629_market_supply_l2_config.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 628", "(SELECT max(version) FROM schema_migrations) <> 628",
			"migration_id='628_global_firewall_redelivery'", "ERRCODE='P6290'",
			"CREATE OR REPLACE FUNCTION assert_line_group_l2_config_504()",
			"NEW.purpose <> 'market_supply' AND config_region <> ''",
			"CREATE OR REPLACE FUNCTION protect_referenced_l2_config_504()",
			"line_group.purpose <> 'market_supply'",
		}, []string{"DELETE FROM", "UPDATE node_line_groups", "DROP TABLE", "DROP TRIGGER", "DROP FUNCTION"}},
		{"629_market_supply_l2_config.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 629", "migration_id='629_market_supply_l2_config'",
			"ERRCODE='P6291'", "ERRCODE='P6292'", "line_group.purpose = 'market_supply'",
			"IF NOT FOUND OR (config_region <> '' AND config_region IS DISTINCT FROM NEW.region) THEN",
		}, []string{"DELETE FROM", "UPDATE node_line_groups", "DROP TABLE", "DROP TRIGGER", "NEW.purpose"}},
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
