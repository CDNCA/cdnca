package migrations

import (
	"strings"
	"testing"
)

// Migration 633 (on top of 632
// dns_provider_cloudns_namecheap_jdcloud): control.db_pool.saturated / recovered notify the platform
// members who can read the maintenance page. Down refuses while such
// notifications exist.
func TestControlDBPoolAlerts633Contract(t *testing.T) {
	variables := "ARRAY['instance','in_use','max_conns','resident_conns','request_capacity','queued','avg_wait_ms','reasons','occurred_at']"
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"633_control_db_pool_alerts.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 632", "(SELECT max(version) FROM schema_migrations) <> 632",
			"WHERE version=632 AND", "migration_id='632_dns_provider_cloudns_namecheap_jdcloud'", "ERRCODE='P6330'",
			"('control.db_pool.saturated', true, true, true, 1, 1, true, true, false, now())",
			"('control.db_pool.recovered', true, true, true, 1, 1, true, true, false, now())",
			"('control.db_pool.saturated.zh-cn', 1, 'sms'", "('control.db_pool.saturated.zh-cn', 1, 'email'",
			"('control.db_pool.recovered.zh-cn', 1, 'sms'", "('control.db_pool.recovered.zh-cn', 1, 'email'",
			variables, "ARRAY['instance','since','cause','occurred_at']",
		}, []string{"DELETE FROM", "UPDATE ", "DROP TABLE"}},
		{"633_control_db_pool_alerts.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 633", "migration_id='633_control_db_pool_alerts'",
			"ERRCODE='P6331'", "ERRCODE='P6332'", "FROM notification_outbox WHERE template_id IN",
			"DELETE FROM admin_inbox_messages WHERE event_type IN ('control.db_pool.saturated', 'control.db_pool.recovered')",
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
