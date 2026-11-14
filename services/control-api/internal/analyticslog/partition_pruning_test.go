package analyticslog

import (
	"strings"
	"testing"
)

func TestPageQueriesUseWindowCandidatesBeforeLatestVersionResolution(t *testing.T) {
	tests := []struct {
		name            string
		query           string
		candidateSource string
	}{
		{name: "access", query: accessPageSQL, candidateSource: "access_event_query_index_state_v1"},
		{name: "security", query: blockEventPageSQL, candidateSource: "security_event_query_index_state_v1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateStart := strings.Index(test.query, "candidate_event_ids AS")
			resolutionStart := strings.Index(test.query, "selected_rows AS")
			payloadStart := strings.Index(test.query, "payload_rows AS")
			if candidateStart < 0 || resolutionStart <= candidateStart || payloadStart <= resolutionStart {
				t.Fatalf("query does not order candidate, latest resolution, and payload stages")
			}
			candidate := test.query[candidateStart:resolutionStart]
			for _, clause := range []string{
				"FROM " + test.candidateSource,
				// the candidates come from the segment the
				// client chose ([segment_from, to) within the window) plus the
				// whole window's ambiguous events, which must still sort first.
				"occurred_at >= segment_from",
				"occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')",
				"ingested_at <= snapshot_at",
				"SELECT event_id FROM conflict_event_ids",
			} {
				if !strings.Contains(candidate, clause) {
					t.Fatalf("candidate scan is missing %q", clause)
				}
			}
			conflictStart := strings.Index(test.query, "conflict_keys AS")
			if conflictStart < 0 || conflictStart > candidateStart {
				t.Fatal("conflict scan is missing before the candidates")
			}
			conflict := test.query[conflictStart:candidateStart]
			for _, clause := range []string{
				"FROM " + test.name + "_event_version_digest_v1 FINAL",
				"version_digest_min != version_digest_max",
				"occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')",
				"occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')",
				"ingested_at <= snapshot_at",
			} {
				if strings.Count(conflict, clause) < 1 {
					t.Fatalf("conflict scan is missing %q", clause)
				}
			}
			latestScan := test.query[resolutionStart:payloadStart]
			// log-read-perf (accepted 10-30): the state rows are pre-filtered
			// to the candidates in PREWHERE instead of an INNER JOIN after the
			// scan, which read the scope's whole retention per page. Measured
			// on 10M access rows (2 cores, 4 GiB): 1h p50 132→32ms, 24h
			// 5787→1712ms (4.24→1.11 GiB read), 7d OOM→11.4s; keeping the join
			// next to the IN made 7d slower (13.7→43.1s). Page output with a
			// fixed snapshot is byte-identical.
			if !strings.Contains(latestScan, "AND event_key IN (SELECT reinterpretAsUInt128(sipHash128(event_id)) FROM candidate_event_ids)\n\t\tWHERE ingested_at <= snapshot_at") {
				t.Fatal("latest-version scan is not restricted to candidate event IDs")
			}
			if !strings.Contains(latestScan, "FROM "+test.candidateSource) ||
				!strings.Contains(latestScan, "WHERE ingested_at <= snapshot_at") {
				t.Fatal("latest state rows are not snapshot-filtered before merge")
			}
			for _, clause := range []string{
				"tupleElement(latest_filter, 1) >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')",
				"tupleElement(latest_filter, 1) >= segment_from",
				"tupleElement(latest_filter, 1) < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')",
			} {
				if !strings.Contains(latestScan, clause) {
					t.Fatalf("latest rows do not reapply %q", clause)
				}
			}
		})
	}
}

func TestPageQueriesTreatOnlyDistinctEqualIngestedPayloadsAsAmbiguous(t *testing.T) {
	for _, test := range []struct {
		name, query, indexState, payloadState, rawTable, evidenceState string
	}{
		{name: "access", query: accessPageSQL, indexState: "access_event_query_index_state_v1",
			payloadState: "access_event_query_payload_state_v1", rawTable: "access_events", evidenceState: "access_version_evidence_v1"},
		{name: "security", query: blockEventPageSQL, indexState: "security_event_query_index_state_v1",
			payloadState: "security_event_query_payload_state_v1", rawTable: "security_events", evidenceState: "security_version_evidence_v1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			latestStart := strings.Index(test.query, "\nSELECT\n")
			if latestStart < 0 {
				t.Fatal("query result SELECT is missing")
			}
			for _, clause := range []string{
				"toDateTime64(initialQueryStartTime(), 3, 'UTC') - INTERVAL 1 MILLISECOND",
				"durable_version_count",
			} {
				if !strings.Contains(test.query, clause) {
					t.Fatalf("query is missing %q", clause)
				}
			}
			for _, clause := range []string{
				"FROM " + test.indexState,
				"FROM " + test.payloadState,
				"argMaxMerge(latest_filter_state) AS latest_filter",
				"argMaxMerge(latest_payload_state) AS latest",
				"uniqExactMerge(version_pair_state)",
				"> uniqExactMerge(ingested_at_state)",
				"AND event_key IN (SELECT reinterpretAsUInt128(sipHash128(event_id)) FROM candidate_event_ids)\n\t\tWHERE ingested_at <= snapshot_at",
				"toUInt64(ifNull(durable_version_count, 1)) AS latest_version_count",
				"HAVING durable_version_count > 1 OR",
				"(tenant_id, event_id) IN (SELECT tupleElement(key, 1), tupleElement(key, 2) FROM (SELECT arrayJoin(tupleElement(selected_keys, 1)) AS key))\n\t\t\tOR event_id IN (SELECT arrayJoin(tupleElement(selected_keys, 2)))",
			} {
				if !strings.Contains(test.query, clause) {
					t.Fatalf("%s query is missing %q", test.name, clause)
				}
			}
			for _, forbidden := range []string{
				test.rawTable, test.evidenceState,
				"raw_version_count", "max_version_count", "any(tuple(", "argMax(version_payload",
			} {
				if strings.Contains(test.query, forbidden) {
					t.Fatalf("%s query retains raw-path fragment %q", test.name, forbidden)
				}
			}
		})
	}
}
