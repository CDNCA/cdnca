package analyticslog

import (
	"strings"
	"testing"
)

func TestAccessQueryUsesPrecomputedStateOnly(t *testing.T) {
	outerSelect := strings.Index(accessPageSQL, "\nSELECT\n    event_id,")
	if outerSelect < 0 {
		t.Fatal("access outer query is missing")
	}
	candidate := accessPageSQL[:outerSelect]
	for _, required := range []string{
		"candidate_event_ids AS",
		"FROM access_event_query_index_state_v1",
		"PREWHERE metric_version = 1",
		"tenant_id = toUUID({tenant_id:String})",
		"occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')",
		"occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')",
		"ingested_at <= snapshot_at",
	} {
		if !strings.Contains(candidate, required) {
			t.Fatalf("access candidate state scan is missing %q", required)
		}
	}
	for _, required := range []string{
		"selected_rows AS",
		"payload_rows AS",
		"FROM access_event_query_payload_state_v1",
		"uniqExactMerge(version_pair_state)",
		"uniqExactMerge(ingested_at_state)",
		"argMaxMerge(latest_filter_state) AS latest_filter",
		"argMaxMerge(latest_payload_state) AS latest",
		"INNER JOIN candidate_event_ids USING (event_id)",
		"event_id IN (SELECT event_id FROM selected_rows)",
		"{has_cursor:UInt8} = 0",
		"event_id < {cursor_event_id:String}",
	} {
		if !strings.Contains(accessPageSQL, required) {
			t.Fatalf("access state query lost %q", required)
		}
	}
	for _, forbidden := range []string{
		"access_events",
		"access_version_evidence_v1",
		"uniqExact(tuple(",
		"argMax(tuple(",
		"raw_version_count",
	} {
		if strings.Contains(accessPageSQL, forbidden) {
			t.Fatalf("access query still contains raw-path fragment %q", forbidden)
		}
	}
}

func TestAccessConflictStatePreservesReplacementSemantics(t *testing.T) {
	if !strings.Contains(accessPageSQL,
		"uniqExactMerge(version_pair_state) > uniqExactMerge(ingested_at_state)") {
		t.Fatal("conflict state does not distinguish replacement timestamps from same-time conflicts")
	}

	tests := []struct {
		name     string
		versions [][2]string
		conflict bool
	}{
		{name: "missing evidence"},
		{name: "identical retry", versions: [][2]string{{"t1", "a"}, {"t1", "a"}}},
		{name: "later replacement", versions: [][2]string{{"t1", "a"}, {"t2", "b"}}},
		{name: "equal-time different payload", versions: [][2]string{{"t1", "a"}, {"t1", "b"}}, conflict: true},
		{name: "historical conflict then replacement", versions: [][2]string{{"t1", "a"}, {"t1", "b"}, {"t2", "c"}}, conflict: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timestamps := make(map[string]struct{}, len(test.versions))
			pairs := make(map[[2]string]struct{}, len(test.versions))
			for _, version := range test.versions {
				timestamps[version[0]] = struct{}{}
				pairs[version] = struct{}{}
			}
			if got := len(pairs) > len(timestamps); got != test.conflict {
				t.Fatalf("set-identity conflict=%t, want %t", got, test.conflict)
			}
		})
	}
}

func TestAccessQueryUsesOneCandidateJoinAndOneEventAggregate(t *testing.T) {
	if got := strings.Count(accessPageSQL, "INNER JOIN candidate_event_ids USING (event_id)"); got != 1 {
		t.Fatalf("candidate CTE join count=%d, want 1", got)
	}
	if strings.Contains(accessPageSQL, "conflict_counts AS") {
		t.Fatal("access query still materializes the candidate-bound conflict aggregate separately")
	}
	for _, required := range []string{
		"SELECT event_id, latest_filter_state, version_pair_state, ingested_at_state",
		"FROM access_event_query_index_state_v1",
		"WHERE ingested_at <= snapshot_at",
		"uniqExactMerge(version_pair_state)",
		"uniqExactMerge(ingested_at_state)",
		"GROUP BY access.event_id",
		"LIMIT {row_limit:UInt16}",
		"FROM access_event_query_payload_state_v1",
		"event_id IN (SELECT event_id FROM selected_rows)",
		"SETTINGS max_threads = 2",
	} {
		if !strings.Contains(accessPageSQL, required) {
			t.Fatalf("single event aggregate is missing %q", required)
		}
	}
}
