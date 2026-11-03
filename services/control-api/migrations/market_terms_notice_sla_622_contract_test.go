package migrations

import (
	"strings"
	"testing"
)

// Migration 622 (on top of 621):
// market.terms.changed v2 templates name what changed (category), the SLA
// included; v1 stays.
func TestMarketTermsNoticeSLA622Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"622_market_terms_notice_sla.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 621", "(SELECT max(version) FROM schema_migrations) <> 621",
			"migration_id='621_certificate_order_outbox_failure'", "ERRCODE='P6220'",
			"('market.terms.changed.zh-cn', 2, 'sms'", "('market.terms.changed.zh-cn', 2, 'email'",
			"ARRAY['offer','subscription','action','category']", "{{.category}}", "sla_worse", "sla_removed", "resale_off", "site_pause_on",
		}, []string{"DELETE FROM", "UPDATE ", "DROP ", "notification_event_policies"}},
		{"622_market_terms_notice_sla.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 622", "migration_id='622_market_terms_notice_sla'",
			"ERRCODE='P6221'", "ERRCODE='P6222'",
			"DELETE FROM notification_templates WHERE template_id = 'market.terms.changed.zh-cn' AND version = 2;",
		}, []string{"version = 1", "DROP "}},
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
