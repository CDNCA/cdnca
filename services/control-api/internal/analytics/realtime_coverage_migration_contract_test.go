package analytics

import (
	"os"
	"strings"
	"testing"
)

func TestSiteRealtimeCoverageAuthorityMigration015RemovesIngestTimeClaim(t *testing.T) {
	up, err := os.ReadFile("../../../../infra/clickhouse/migrations/015_site_realtime_coverage_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../../infra/clickhouse/migrations/015_site_realtime_coverage_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, token := range []string{
		"predecessor_up_sha256=373fc236fa24eee7d14b0d10c254ab68481ec4561dea8a2789cc2fad3677ad2a",
		"predecessor_down_sha256=6e086f88815da358efbbc69ddc1e0a7d0de4e80830798ac6eef6fe28f7ee6b38",
		"UPDATE source_watermark = 0", "finalized_through = toDateTime64(0, 3, 'UTC')",
		"toUInt64(0) AS source_watermark", "SETTINGS mutations_sync = 2",
		"CREATE MATERIALIZED VIEW IF NOT EXISTS site_realtime_access_facts_mv_v1",
	} {
		if !strings.Contains(upText, token) {
			t.Errorf("migration 015 up missing %q", token)
		}
	}
	if strings.Contains(upText, "ingested_at AS finalized_through") ||
		strings.Contains(upText, "toUInt64(toUnixTimestamp64Milli(ingested_at)) AS source_watermark") {
		t.Fatal("migration 015 continues treating ingest time as source coverage")
	}
	for _, token := range []string{
		"UPDATE source_watermark = toUInt64(toUnixTimestamp64Milli(ingested_at))",
		"ingested_at AS finalized_through", "SETTINGS mutations_sync = 2",
	} {
		if !strings.Contains(downText, token) {
			t.Errorf("migration 015 down missing %q", token)
		}
	}
}
