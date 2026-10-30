package analyticslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyticsLogQueryProjectionMigrationContract(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	read := func(parts ...string) string {
		contents, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(contents)
	}
	up := read("infra", "clickhouse", "migrations", "012_analytics_log_query_projection.up.sql")
	down := read("infra", "clickhouse", "migrations", "012_analytics_log_query_projection.down.sql")
	legacyAccessPayloadBackfill := `INSERT INTO access_event_query_payload_state_v1
    (metric_version, tenant_id, event_id, ingested_at, occurred_at, latest_payload_state,
     version_pair_state, ingested_at_state)
SELECT`
	if !strings.Contains(up, legacyAccessPayloadBackfill) {
		t.Fatal("012 access payload backfill must name its legacy columns before later migrations extend the table")
	}

	for _, name := range []string{"access", "security"} {
		indexTable := name + "_event_query_index_state_v1"
		payloadTable := name + "_event_query_payload_state_v1"
		for _, required := range []string{
			"CREATE TABLE IF NOT EXISTS " + indexTable,
			"CREATE TABLE IF NOT EXISTS " + payloadTable,
			"CREATE MATERIALIZED VIEW IF NOT EXISTS " + name + "_event_query_index_mv_v1",
			"CREATE MATERIALIZED VIEW IF NOT EXISTS " + name + "_event_query_payload_mv_v1",
			"INSERT INTO " + indexTable,
			"INSERT INTO " + payloadTable,
			"argMaxState(tuple(",
			"uniqExactState(tuple(ingested_at, payload_digest))",
			"uniqExactState(ingested_at)",
			"hex(SHA256(toJSONString(tuple(",
		} {
			if !strings.Contains(up, required) {
				t.Errorf("012 migration is missing %q", required)
			}
		}
		indexStart := strings.Index(up, "CREATE TABLE IF NOT EXISTS "+indexTable)
		payloadStart := strings.Index(up, "CREATE TABLE IF NOT EXISTS "+payloadTable)
		if indexStart < 0 || payloadStart <= indexStart {
			t.Fatalf("%s projection table boundaries are missing", name)
		}
		indexDDL := up[indexStart:payloadStart]
		for _, sensitive := range []string{"request_headers", "response_headers", "request_body", "response_body", "latest_payload_state"} {
			if strings.Contains(indexDDL, sensitive) {
				t.Errorf("%s narrow query index contains sensitive/full payload field %q", name, sensitive)
			}
		}
		view := strings.Index(up, "CREATE MATERIALIZED VIEW IF NOT EXISTS "+name+"_event_query_index_mv_v1")
		backfill := strings.Index(up, "INSERT INTO "+indexTable)
		if view < 0 || backfill <= view {
			t.Errorf("%s query projection must install its MV before the idempotent state backfill", name)
		}
		for _, object := range []string{"payload", "index"} {
			viewDrop := strings.Index(down, "DROP VIEW IF EXISTS "+name+"_event_query_"+object+"_mv_v1")
			tableDrop := strings.Index(down, "DROP TABLE IF EXISTS "+name+"_event_query_"+object+"_state_v1 SYNC")
			if viewDrop < 0 || tableDrop <= viewDrop {
				t.Errorf("%s %s projection down must drop the MV before its target table", name, object)
			}
		}
	}
	for _, ttl := range []string{
		"TTL toDateTime(occurred_at, 'UTC') + INTERVAL 30 DAY DELETE",
		"TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE",
	} {
		if strings.Count(up, ttl) != 2 {
			t.Errorf("projection TTL %q count=%d, want 2", ttl, strings.Count(up, ttl))
		}
	}

	// the cluster DDL of 012 is its replicated mirror file, statement by statement
	assertReplicatedMirror(t, repoRoot, "012_analytics_log_query_projection.up.sql", up)
	assertReplicatedMirror(t, repoRoot, "012_analytics_log_query_projection.down.sql", down)
}
