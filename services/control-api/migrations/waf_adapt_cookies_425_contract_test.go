package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 425（站点 Cookie 名集合）是占位号：合入时统一改号，
// 随改号变化的内容都集中在这里。
const (
	wafAdaptCookiesMigrationVersion         = 425
	wafAdaptCookiesMigrationID              = "425_waf_adapt_cookies"
	wafAdaptCookiesMigrationPreviousVersion = 424
	wafAdaptCookiesMigrationPreviousID      = "424_rule_intel_report_state"
	wafAdaptCookiesMigrationPreviousUpSHA   = ruleIntelReportMigrationUpSHA
	wafAdaptCookiesMigrationPreviousDownSHA = ruleIntelReportMigrationDownSHA
	wafAdaptCookiesMigrationUpSHA           = "ab8f82e51340a050dd670d3e396ee986d05790ee7c0824dfd028afa09815b135"
	wafAdaptCookiesMigrationDownSHA         = "ef214d732072f69dd538451c2b961998d32e402d5e45c857aee80546bb2840c8"
)

func TestWAFAdaptCookiesContract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{wafAdaptCookiesMigrationID + ".up.sql", wafAdaptCookiesMigrationUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", wafAdaptCookiesMigrationPreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", wafAdaptCookiesMigrationPreviousVersion),
			"migration_id='" + wafAdaptCookiesMigrationPreviousID + "'", wafAdaptCookiesMigrationPreviousUpSHA, wafAdaptCookiesMigrationPreviousDownSHA,
			"ERRCODE='P4250'", "CREATE TABLE waf_adapt_cookies", "ADD COLUMN cookie_samples",
		}},
		{wafAdaptCookiesMigrationID + ".down.sql", wafAdaptCookiesMigrationDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", wafAdaptCookiesMigrationVersion),
			"migration_id='" + wafAdaptCookiesMigrationID + "'", "ERRCODE='P4251'", "DROP TABLE waf_adapt_cookies",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
