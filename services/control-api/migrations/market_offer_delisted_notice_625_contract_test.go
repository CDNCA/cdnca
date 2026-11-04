package migrations

import (
	"strings"
	"testing"
)

// Migration 625 (on top of 624):
// market.terms.changed v3 templates add at and say "the seller delisted it,
// no renewal after at" for category offer_delisted; v1/v2 stay (marketruntime
// noticeTemplateVersions picks v3; TestTermsChangedV3TemplatesRender renders them).
func TestMarketOfferDelistedNotice625Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"625_market_offer_delisted_notice.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 624", "(SELECT max(version) FROM schema_migrations) <> 624",
			"migration_id='624_market_subscribed_line_nodes'", "ERRCODE='P6250'",
			"('market.terms.changed.zh-cn', 3, 'sms'", "('market.terms.changed.zh-cn', 3, 'email'",
			"ARRAY['offer','subscription','action','category','at']", `{{if eq .category "offer_delisted"}}`, "{{.at}}", "不再续费",
		}, []string{"DELETE FROM", "UPDATE ", "DROP ", "notification_event_policies"}},
		{"625_market_offer_delisted_notice.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 625", "migration_id='625_market_offer_delisted_notice'",
			"ERRCODE='P6251'", "ERRCODE='P6252'",
			"DELETE FROM notification_templates WHERE template_id = 'market.terms.changed.zh-cn' AND version = 3;",
		}, []string{"version = 2", "version = 1", "DROP "}},
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
