package migrations

import (
	"strings"
	"testing"
)

// Migration 623 (on top of 622): a
// market supply can be disabled on this controller only (local DNS skips
// it), and each leaf keeps the blockers of its last rollout for the page.
func TestMarketSupplyLocalDisable623Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"623_market_supply_local_disable.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 622", "(SELECT max(version) FROM schema_migrations) <> 622",
			"migration_id='622_market_terms_notice_sla'", "ERRCODE='P6230'",
			"ALTER TABLE site_supplies ADD COLUMN local_disabled_at timestamptz;",
			"local_disabled_at IS NULL OR kind = 'market_subscription'",
			"ADD COLUMN blockers jsonb NOT NULL DEFAULT '[]'::jsonb", "ADD COLUMN blockers_revision bigint NOT NULL DEFAULT 0",
		}, []string{"DELETE FROM", "UPDATE ", "DROP "}},
		{"623_market_supply_local_disable.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 623", "migration_id='623_market_supply_local_disable'",
			"ERRCODE='P6231'", "DROP COLUMN local_disabled_at", "DROP COLUMN blockers_revision, DROP COLUMN blockers",
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
