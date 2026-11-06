package migrations

import (
	"strings"
	"testing"
)

// Migration 635 (predecessor 634_market_stale_commit):
// the leaf writes a subscriber's ban list snapshot as source market rows keyed
// by the subscriber's entry, and the subscriber records
// what each leaf took. Down drops the copies and restores the 415 check.
func TestMarketBanSync635Contract(t *testing.T) {
	up := readBanSync635(t, "up")
	down := readBanSync635(t, "down")
	for _, fragment := range []string{
		"ERRCODE='P6350'", "to_regclass(current_schema() || '.market_supply_site_revisions') IS NULL",
		"DROP CONSTRAINT security_ban_entries_source_415",
		"CHECK (source IN ('waf', 'cc', 'manual', 'autodefense', 'market'))",
		"CREATE TABLE market_supply_ban_refs", "PRIMARY KEY (tenant_scope_id, site_id, ref)",
		"entry_id uuid NOT NULL UNIQUE REFERENCES security_ban_entries(id) ON DELETE CASCADE",
		"release_cause text CHECK (release_cause IN ('buyer', 'subscription'))",
		"CREATE TABLE market_supply_ban_sites", "CREATE TABLE site_supply_ban_deliveries",
		"state text NOT NULL CHECK (state IN ('sent', 'accepted', 'rejected', 'unsupported'))",
		"REVOKE ALL ON market_supply_ban_refs, market_supply_ban_sites, site_supply_ban_deliveries FROM PUBLIC",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("635 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"ERRCODE='P6351'", "DROP TABLE site_supply_ban_deliveries", "DROP TABLE market_supply_ban_sites",
		"DROP TABLE market_supply_ban_refs", "DELETE FROM security_ban_entries WHERE source = 'market'",
		"ADD CONSTRAINT security_ban_entries_source_415\n    CHECK (source IN ('waf', 'cc', 'manual', 'autodefense'))",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("635 down missing %q", fragment)
		}
	}
	// Up only adds: no existing row is rewritten or removed.
	for _, forbidden := range []string{"DELETE FROM", "UPDATE security_ban_entries"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("635 up must not contain %q", forbidden)
		}
	}
}

// readBanSync635 reads the 635 script.
func readBanSync635(t *testing.T, direction string) string {
	t.Helper()
	for _, name := range []string{"635_market_ban_sync."} {
		if body, err := FS.ReadFile(name + direction + ".sql"); err == nil {
			return string(body)
		}
	}
	t.Fatalf("635 %s script not found", direction)
	return ""
}
