package analytics

import (
	"os"
	"strings"
	"testing"
)

func TestSiteRealtimeClickHouseMigrationContract(t *testing.T) {
	up, err := os.ReadFile("../../../../infra/clickhouse/migrations/009_site_realtime_monitoring.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../../infra/clickhouse/migrations/009_site_realtime_monitoring.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"predecessor_up_sha256=", "ALTER TABLE access_events", "listen_port UInt16 DEFAULT 0", "lower(host)",
		"site_realtime_access_facts_v1", "MATERIALIZED VIEW", "PARTITION BY", "TTL", "source_watermark", "finalized_through"} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("up migration missing %q", required)
		}
	}
	for _, required := range []string{"DROP VIEW IF EXISTS site_realtime_access_facts_mv_v1", "DROP TABLE IF EXISTS site_realtime_access_facts_v1", "DROP COLUMN IF EXISTS listen_port"} {
		if !strings.Contains(string(down), required) {
			t.Fatalf("down migration missing %q", required)
		}
	}
}

func TestSiteRealtimePostgresMigration131AndAggregateMountContract(t *testing.T) {
	up, err := os.ReadFile("../../migrations/131_analytics_realtime_expected_counts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/131_analytics_realtime_expected_counts.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 131 requires the exact verified 130 release head",
		"32ba9ecf6db54415a10985cd1331d65338a27e1948fce53a1b9a5d7aebc628b3",
		"f1f263da30b26f45ebf98e9be5c056af93fa3ded6c8c529068b54fd223cb5f2c",
		"CREATE TABLE analytics_realtime_expected_counts_131",
		"REFERENCES analytics_ingest_receipts(history_epoch,stream_sequence)",
		"hour=date_trunc('hour',hour)", "listen_port BETWEEN 0 AND 65535", "expected_events BETWEEN 1 AND 1000",
		"guard_analytics_realtime_expected_count_131", "ERRCODE='P1310'",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("131 up migration missing %q", required)
		}
	}
	for _, required := range []string{"rollback would discard realtime expected counts", "ERRCODE='P1311'",
		"DROP TABLE analytics_realtime_expected_counts_131", "DROP FUNCTION guard_analytics_realtime_expected_count_131()"} {
		if !strings.Contains(string(down), required) {
			t.Errorf("131 down migration missing %q", required)
		}
	}
	aggregate, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"../../control-analytics.openapi.yaml#/paths/~1v1~1admin~1analytics~1site-realtime",
		"../../control-analytics.openapi.yaml#/paths/~1v1~1analytics~1site-realtime",
	} {
		if !strings.Contains(string(aggregate), required) {
			t.Errorf("aggregate OpenAPI missing %q", required)
		}
	}
}

func TestSiteRealtimeSourceWindowAuthorityMigration184Contract(t *testing.T) {
	up, err := os.ReadFile("../../migrations/184_analytics_realtime_source_window_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/184_analytics_realtime_source_window_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 184 requires the exact verified 183 release head",
		"6b9944051f89399f001da2943cc9407904961c2149b4f3091c42b3e9dadca590",
		"75d27e61685c7a963f197b42d344d958692db03e061b9166728fc603bf59d38c",
		"CREATE TABLE analytics_realtime_source_windows_184",
		"window_end=window_start+interval '1 hour'",
		"access_sources_finalized<=access_sources_expected",
		"connection_sources_finalized<=connection_sources_expected",
		"guard_analytics_realtime_source_window_184",
		"analytics realtime source windows are immutable",
		"BEFORE UPDATE OR DELETE",
		"BEFORE TRUNCATE",
		"REVOKE ALL ON analytics_realtime_source_windows_184 FROM PUBLIC",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("184 up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 184 rollback requires the exact verified 184 and 183 release heads",
		"rollback would discard realtime source window evidence",
		"DROP TABLE analytics_realtime_source_windows_184",
		"DROP FUNCTION guard_analytics_realtime_source_window_184()",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("184 down migration missing %q", required)
		}
	}
}
