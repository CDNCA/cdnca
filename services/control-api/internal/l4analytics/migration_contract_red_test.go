package l4analytics

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL4ClickHouseMigrationKeepsHighCardinalityFactsOutOfPostgres(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../"))
	up, err := os.ReadFile(filepath.Join(root, "infra/clickhouse/migrations/011_l4_session_facts.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(up)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS l4_session_facts_v1",
		"tenant_id UUID", "node_id UUID", "site_id UUID", "stream_id UUID", "listener_id UUID",
		"session_id String", "started_at DateTime64", "finalized_at DateTime64",
		"bytes_up UInt64", "bytes_down UInt64", "status_code UInt16", "error_code LowCardinality(String)",
		"config_version_id UUID", "traceparent String", "task_id String", "source_watermark UInt64",
		"evidence_sha256 FixedString(64)", "canonical_event_sha256 FixedString(64)",
		"PARTITION BY toYYYYMM(finalized_at)", "TTL toDateTime(finalized_at, 'UTC') + INTERVAL 30 DAY DELETE",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("L4 ClickHouse migration omitted %q", want)
		}
	}
	if strings.Contains(strings.ToLower(text), "remote_addr") || strings.Contains(strings.ToLower(text), "upstream_addr") {
		t.Fatal("L4 fact schema persisted a sensitive raw address")
	}
}
