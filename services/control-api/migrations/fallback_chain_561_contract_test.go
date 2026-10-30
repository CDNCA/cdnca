package migrations

import (
	"strings"
	"testing"
)

// Migration 561: the platform default fallback chain,
// per-site overrides, chain-maintained supply bindings and the backup_group /
// attack_overflow / locked values of the aggregated edge schedule. The 552
// predecessor is pinned by checksum (re-pinned when 553–561 merge).
func TestFallbackChain561Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"561_fallback_chain.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 560", "(SELECT max(version) FROM schema_migrations) <> 560",
			"migration_id='560_autodefense_admin_login_allows'",
			"checksum_sha256='6730caea4013f8f96f7011b0ec52739f49f558012f18704800762d670bfcb307'",
			"down_checksum_sha256='845255d88b7ad124f5c4ac1f912847edca32a95b6d38a101a90322ebf6fe6b28'",
			"ERRCODE='P5610'", "CREATE TABLE fallback_chain_settings", "CREATE TABLE fallback_chain_site_overrides", "CREATE TABLE fallback_chain_own_health",
			"enabled boolean NOT NULL DEFAULT true",
			"ARRAY['local', 'backup_group', 'market_subscription', 'third_party_cdn']",
			"INSERT INTO fallback_chain_settings(singleton, updated_at)",
			"site_supply_bindings_source_561_check CHECK (source IN ('manual', 'fallback_chain'))",
			"aggregated_edge_line_targets_kind_561_check", "kind <> 'backup_group' OR line_scope = ''",
			"aggregated_edge_switch_events_reason_561_check", "'attack_overflow'",
			"aggregated_edge_site_schedules_frozen_reason_561_check", "('', 'flap_limit', 'locked')",
			"GRANT SELECT, UPDATE ON fallback_chain_settings TO cdnca_control_app, cdnca_control_runtime",
			// 最后一级二选一：默认无限防线路组，未选回落黑洞，单站可覆盖为黑洞。
			"last_resort text NOT NULL DEFAULT 'unlimited' CHECK (last_resort IN ('blackhole', 'unlimited'))",
			"REFERENCES node_line_groups(tenant_scope_id, id)",
			"last_resort text NOT NULL DEFAULT 'inherit' CHECK (last_resort IN ('inherit', 'blackhole'))",
			"mode text NOT NULL CHECK (mode IN ('inherit', 'off', 'custom'))",
			"escalate_site_states_c_via_561_check", "'unlimited'))",
			"('security.escalate.unlimited', true, true, true, 1, 1, true, true, true, now())",
			"'security.escalate.unlimited.zh-cn', 1, 'sms'", "'security.escalate.unlimited.zh-cn', 1, 'email'",
		}},
		{"561_fallback_chain.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 561", "migration_id='561_fallback_chain'",
			"ERRCODE='P5611'", "DELETE FROM site_supply_bindings WHERE source='fallback_chain'",
			"aggregated_edge_switch_events_reason_460_check", "aggregated_edge_line_targets_kind_check",
			"DROP TABLE fallback_chain_own_health", "DROP TABLE fallback_chain_settings",
			"ERRCODE='P5612'", "DELETE FROM notification_event_policies WHERE event_type = 'security.escalate.unlimited'",
			"escalate_site_states_c_via_check", "UPDATE escalate_site_states SET c_via='line_group' WHERE c_via='unlimited'",
		}},
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
	}
}
