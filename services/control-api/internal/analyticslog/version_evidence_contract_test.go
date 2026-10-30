package analyticslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionEvidenceContract(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	checks := []struct {
		path  string
		parts []string
	}{
		{
			path: filepath.Join(repoRoot, "infra", "clickhouse", "migrations", "004_analytics_version_evidence.up.sql"),
			parts: []string{
				"access_version_evidence_v1",
				"security_version_evidence_v1",
				"payload_digest",
				"payload_snapshot",
				"SHA256",
				"ReplacingMergeTree",
				"CREATE MATERIALIZED VIEW",
				"ingested_at DateTime64(3, 'UTC')",
				"TTL toDateTime(ingested_at, 'UTC') + INTERVAL 400 DAY DELETE",
			},
		},
		{
			path: filepath.Join(repoRoot, "infra", "clickhouse", "migrations", "006_access_event_state.up.sql"),
			parts: []string{
				"access_event_latest_state_v1",
				"access_event_conflict_state_v1",
				"AggregateFunction(argMax",
				"AggregateFunction(uniqExact",
				"argMaxState(tuple(",
				"uniqExactState(tuple(ingested_at, payload_digest))",
			},
		},
		{
			// the cluster mirror of 004 (infra/clickhouse/replicated, one file per migration)
			path: filepath.Join(repoRoot, "infra", "clickhouse", "replicated", "004_analytics_version_evidence.up.sql"),
			parts: []string{
				"access_version_evidence_v1",
				"security_version_evidence_v1",
				"ReplicatedReplacingMergeTree",
				"task_id, installation_id, request_headers, response_headers, request_body",
				"origin_connect_us, origin_first_byte_us, origin_total_us",
				"INSERT INTO access_version_evidence_v1",
				"INSERT INTO security_version_evidence_v1",
			},
		},
	}
	for _, check := range checks {
		contents, err := os.ReadFile(check.path)
		if err != nil {
			t.Errorf("required version evidence contract %s: %v", check.path, err)
			continue
		}
		for _, part := range check.parts {
			if !strings.Contains(string(contents), part) {
				t.Errorf("version evidence contract %s is missing %q", check.path, part)
			}
		}
	}
	for name, query := range map[string]string{"access": accessPageSQL, "security": blockEventPageSQL} {
		if strings.Contains(query, "durable_version_counts AS\n(") {
			t.Errorf("%s query uses an unsupported durable version CTE shape", name)
		}
		for _, required := range []string{
			name + "_event_query_index_state_v1",
			name + "_event_query_payload_state_v1",
			"argMaxMerge(latest_payload_state)",
			"uniqExactMerge(version_pair_state)",
			"uniqExactMerge(ingested_at_state)",
			"INNER JOIN candidate_event_ids USING (event_id)",
		} {
			if !strings.Contains(query, required) {
				t.Errorf("%s query does not use precomputed evidence state %q", name, required)
			}
		}
		for _, forbidden := range []string{name + "_events", name + "_version_evidence_v1", "payload_digest"} {
			if strings.Contains(query, forbidden) {
				t.Errorf("%s query still uses raw evidence fragment %q", name, forbidden)
			}
		}
	}
}
