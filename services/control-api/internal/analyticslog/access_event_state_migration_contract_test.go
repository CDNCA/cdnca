package analyticslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessEventStateMigrationContract(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	up := readAccessEventStateMigration(t, filepath.Join(repoRoot, "infra", "clickhouse", "migrations",
		"006_access_event_state.up.sql"))
	down := readAccessEventStateMigration(t, filepath.Join(repoRoot, "infra", "clickhouse", "migrations",
		"006_access_event_state.down.sql"))

	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS access_event_latest_state_v1",
		"CREATE TABLE IF NOT EXISTS access_event_conflict_state_v1",
		"ENGINE = AggregatingMergeTree",
		"latest_payload_state AggregateFunction(argMax, Tuple(",
		"latest_ingested_at_state AggregateFunction(max, DateTime64(3, 'UTC'))",
		"version_pair_state AggregateFunction(uniqExact, Tuple(DateTime64(3, 'UTC'), String))",
		"ingested_at_state AggregateFunction(uniqExact, DateTime64(3, 'UTC'))",
		"ORDER BY (tenant_id, event_id, metric_version, ingested_at, occurred_at)",
		"ORDER BY (tenant_id, event_id, metric_version, ingested_at)",
		"TTL toDateTime(occurred_at, 'UTC') + INTERVAL 30 DAY DELETE",
		"TTL toDateTime(ingested_at, 'UTC') + INTERVAL 400 DAY DELETE",
		"CREATE MATERIALIZED VIEW IF NOT EXISTS access_event_latest_state_mv_v1",
		"CREATE MATERIALIZED VIEW IF NOT EXISTS access_event_conflict_state_mv_v1",
		"TO access_event_latest_state_v1",
		"TO access_event_conflict_state_v1",
		"argMaxState(tuple(",
		"maxState(ingested_at) AS latest_ingested_at_state",
		"uniqExactState(tuple(ingested_at, payload_digest)) AS version_pair_state",
		"uniqExactState(ingested_at) AS ingested_at_state",
		"INSERT INTO access_event_latest_state_v1",
		"INSERT INTO access_event_conflict_state_v1",
		"FROM access_events",
		"FROM access_version_evidence_v1",
		"package_subscription_id",
		"request_headers",
		"response_headers",
		"request_body",
		"response_body",
		"origin_total_us",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("006 access event state up migration is missing %q", required)
		}
	}
	for _, forbidden := range []string{"uniqCombined", "uniqHLL12", "uniqTheta", "SHA256", "connection"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("006 access event state migration contains forbidden %q", forbidden)
		}
	}
	if strings.Count(up, "ENGINE = AggregatingMergeTree") != 2 ||
		strings.Count(up, "CREATE MATERIALIZED VIEW IF NOT EXISTS access_event_") != 2 ||
		strings.Count(up, "INSERT INTO access_event_") != 2 {
		t.Fatal("006 access event state migration must define exactly two state tables, views, and backfills")
	}
	for _, object := range []string{"latest", "conflict"} {
		view := strings.Index(up, "CREATE MATERIALIZED VIEW IF NOT EXISTS access_event_"+object+"_state_mv_v1")
		backfill := strings.Index(up, "INSERT INTO access_event_"+object+"_state_v1")
		if view < 0 || backfill < 0 || view > backfill {
			t.Errorf("%s state materialized view must be installed before its idempotent backfill", object)
		}
	}

	for _, required := range []string{
		"DROP VIEW IF EXISTS access_event_conflict_state_mv_v1",
		"DROP VIEW IF EXISTS access_event_latest_state_mv_v1",
		"DROP TABLE IF EXISTS access_event_conflict_state_v1 SYNC",
		"DROP TABLE IF EXISTS access_event_latest_state_v1 SYNC",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("006 access event state down migration is missing %q", required)
		}
	}
	if strings.Index(down, "DROP VIEW IF EXISTS access_event_latest_state_mv_v1") >
		strings.Index(down, "DROP TABLE IF EXISTS access_event_latest_state_v1 SYNC") ||
		strings.Index(down, "DROP VIEW IF EXISTS access_event_conflict_state_mv_v1") >
			strings.Index(down, "DROP TABLE IF EXISTS access_event_conflict_state_v1 SYNC") {
		t.Fatal("006 access event state down migration must drop materialized views before target tables")
	}

	// the cluster DDL of 006 is its replicated mirror file, statement by statement
	assertReplicatedMirror(t, repoRoot, "006_access_event_state.up.sql", up)
	assertReplicatedMirror(t, repoRoot, "006_access_event_state.down.sql", down)
}

func TestAccessEventStateConflictIdentity(t *testing.T) {
	tests := []struct {
		name     string
		versions [][2]string
		want     uint64
	}{
		{name: "missing evidence", want: 1},
		{name: "identical retry", versions: [][2]string{{"t1", "a"}, {"t1", "a"}}, want: 1},
		{name: "later replacement", versions: [][2]string{{"t1", "a"}, {"t2", "b"}}, want: 1},
		{name: "equal-time conflict", versions: [][2]string{{"t1", "a"}, {"t1", "b"}}, want: 2},
		{name: "historical conflict", versions: [][2]string{{"t1", "a"}, {"t1", "b"}, {"t2", "c"}}, want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timestamps := make(map[string]struct{}, len(test.versions))
			pairs := make(map[[2]string]struct{}, len(test.versions))
			for _, version := range test.versions {
				timestamps[version[0]] = struct{}{}
				pairs[version] = struct{}{}
			}
			got := uint64(1)
			if len(pairs) > len(timestamps) {
				got = 2
			}
			if got != test.want {
				t.Fatalf("conflict state=%d, want %d", got, test.want)
			}
		})
	}
}

func readAccessEventStateMigration(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read access event state migration %s: %v", path, err)
	}
	return string(contents)
}
