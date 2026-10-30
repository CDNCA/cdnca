package analyticslog

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	securityStatePredecessorUpSHA   = "255d9499416c52fa8d060f1274584a13c36ee5cf2d0524132a09e9e76327b570"
	securityStatePredecessorDownSHA = "dcded68e17c2de0584b73da7ff1770f9f728b7da85336a5c0e9a1f0838537059"
	// the generated cluster mirror of 008 (infra/clickhouse/replicated)
	securityStateReplicatedUpSHA   = "f389be4239e54e8f9a372cd08460ab0d763b6e731ba97304f10bbd6e8cba30f9"
	securityStateReplicatedDownSHA = "54bebe861a5423c577f855fb11b8516d2a8add6d50c6d986e046e67fa9fe03e8"
)

func TestSecurityQueryUsesPrecomputedStateOnly(t *testing.T) {
	outerSelect := strings.Index(blockEventPageSQL, "\nSELECT\n    event_id,")
	if outerSelect < 0 {
		t.Fatal("security outer query is missing")
	}
	candidate := blockEventPageSQL[:outerSelect]
	for _, required := range []string{
		"candidate_event_ids AS",
		"FROM security_event_query_index_state_v1",
		"PREWHERE metric_version = 1",
		"tenant_id = toUUID({tenant_id:String})",
		"occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')",
		"occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')",
		"ingested_at <= snapshot_at",
	} {
		if !strings.Contains(candidate, required) {
			t.Fatalf("security candidate state scan is missing %q", required)
		}
	}
	for _, required := range []string{
		"selected_rows AS",
		"payload_rows AS",
		"FROM security_event_query_payload_state_v1",
		"argMaxMerge(latest_filter_state) AS latest_filter",
		"argMaxMerge(latest_payload_state) AS latest",
		"uniqExactMerge(version_pair_state)",
		"uniqExactMerge(ingested_at_state)",
		"INNER JOIN candidate_event_ids USING (event_id)",
		"tupleElement(latest_filter, 9) IN ('block', 'challenge', 'log', 'temporary_ban')",
		"({has_action:UInt8} = 0 OR tupleElement(latest_filter, 9) = {action:String})",
		"event_id IN (SELECT event_id FROM selected_rows)",
		"{has_cursor:UInt8} = 0",
		"event_id < {cursor_event_id:String}",
		"SETTINGS max_threads = 2",
	} {
		if !strings.Contains(blockEventPageSQL, required) {
			t.Fatalf("security state query lost %q", required)
		}
	}
	for _, forbidden := range []string{
		"security_events",
		"security_version_evidence_v1",
		"uniqExact(tuple(",
		"argMax(version_payload",
		"max_version_count",
	} {
		if strings.Contains(blockEventPageSQL, forbidden) {
			t.Fatalf("security query still contains raw-path fragment %q", forbidden)
		}
	}
}

func TestSecurityStateMigrationContract(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	read := func(path ...string) string {
		contents, err := os.ReadFile(filepath.Join(path...))
		if err != nil {
			t.Fatalf("read security state migration: %v", err)
		}
		return string(contents)
	}
	up := read(repoRoot, "infra", "clickhouse", "migrations", "008_security_event_state.up.sql")
	down := read(repoRoot, "infra", "clickhouse", "migrations", "008_security_event_state.down.sql")
	predecessorUp := read(repoRoot, "infra", "clickhouse", "migrations", "007_connections_ingest_receipts.up.sql")
	predecessorDown := read(repoRoot, "infra", "clickhouse", "migrations", "007_connections_ingest_receipts.down.sql")
	replicatedUp := read(repoRoot, "infra", "clickhouse", "replicated", "008_security_event_state.up.sql")
	replicatedDown := read(repoRoot, "infra", "clickhouse", "replicated", "008_security_event_state.down.sql")
	for _, frozen := range []struct {
		name, contents, sha string
	}{
		{name: "007 up predecessor", contents: predecessorUp, sha: securityStatePredecessorUpSHA},
		{name: "007 down predecessor", contents: predecessorDown, sha: securityStatePredecessorDownSHA},
		{name: "replicated up fixture", contents: replicatedUp, sha: securityStateReplicatedUpSHA},
		{name: "replicated down fixture", contents: replicatedDown, sha: securityStateReplicatedDownSHA},
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(frozen.contents))); got != frozen.sha {
			t.Fatalf("%s SHA-256=%s, want %s", frozen.name, got, frozen.sha)
		}
	}
	for _, required := range []string{
		"security_event_latest_state_v1",
		"security_event_conflict_state_v1",
		"AggregateFunction(argMax",
		"AggregateFunction(uniqExact",
		"argMaxState(tuple(",
		"uniqExactState(tuple(ingested_at, payload_digest))",
		"TTL toDateTime(occurred_at, 'UTC') + INTERVAL 90 DAY DELETE",
		"TTL toDateTime(ingested_at, 'UTC') + INTERVAL 400 DAY DELETE",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("security state migration is missing %q", required)
		}
	}
	// the cluster DDL of 008 is its replicated mirror file, statement by statement
	assertReplicatedMirror(t, repoRoot, "008_security_event_state.up.sql", up)
	assertReplicatedMirror(t, repoRoot, "008_security_event_state.down.sql", down)
}

func TestSecurityConflictStatePreservesReplacementSemantics(t *testing.T) {
	if !strings.Contains(blockEventPageSQL,
		"uniqExactMerge(version_pair_state) > uniqExactMerge(ingested_at_state)") {
		t.Fatal("security conflict state does not distinguish replacements from same-time conflicts")
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
