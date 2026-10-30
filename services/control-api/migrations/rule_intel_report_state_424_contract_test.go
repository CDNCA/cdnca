package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 424（规则情报上报状态行；本分支 416，ri-wire 排在 417 waf_adapt 后为 424）是占位号：合入时改为预留的 420，
// 随改号变化的内容都集中在这里。
const (
	ruleIntelReportMigrationVersion         = 424
	ruleIntelReportMigrationID              = "424_rule_intel_report_state"
	ruleIntelReportMigrationPreviousVersion = 423
	ruleIntelReportMigrationPreviousID      = "423_waf_adapt"
	ruleIntelReportMigrationPreviousUpSHA   = "a96f39b3ce63fc7fb8325e530bef43bd58526c006db914409cd1960ad2fbbe7c"
	ruleIntelReportMigrationPreviousDownSHA = "938c271f6d5053acf34337408443fbd02d3077aac719f48c9c3f5d8d08acb2ba"
	ruleIntelReportMigrationUpSHA           = "95bbc6c2d73c3fc2731dbf024615dcc0e350013081c05e502c771c5b04ec2f12"
	ruleIntelReportMigrationDownSHA         = "6251b5b4389516bb7e69b90047c6c4038463f2457bf52a242a111807ce018025"
)

func TestRuleIntelReportStateContract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{ruleIntelReportMigrationID + ".up.sql", ruleIntelReportMigrationUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", ruleIntelReportMigrationPreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", ruleIntelReportMigrationPreviousVersion),
			"migration_id='" + ruleIntelReportMigrationPreviousID + "'", ruleIntelReportMigrationPreviousUpSHA, ruleIntelReportMigrationPreviousDownSHA,
			"ERRCODE='P4240'", "CREATE TABLE rule_intel_report_state", "'deferred_too_large'",
		}},
		{ruleIntelReportMigrationID + ".down.sql", ruleIntelReportMigrationDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", ruleIntelReportMigrationVersion),
			"migration_id='" + ruleIntelReportMigrationID + "'", "ERRCODE='P4241'", "DROP TABLE rule_intel_report_state",
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
