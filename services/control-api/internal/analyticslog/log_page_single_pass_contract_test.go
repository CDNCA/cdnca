package analyticslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each expensive CTE of a page query runs once. ClickHouse evaluates
// a scalar subquery once per query only when it holds no non-deterministic
// function, so the page SQL takes its snapshot from initialQueryStartTime and
// reaches conflict_keys and selected_rows only through one scalar each.
func TestPageQueriesReadEachExpensiveStageOnce(t *testing.T) {
	for name, query := range map[string]string{"access": accessPageSQL, "security": blockEventPageSQL} {
		if strings.Contains(query, "now64(") {
			t.Errorf("%s page query uses now64, which re-evaluates every scalar subquery per reference", name)
		}
		for fragment, want := range map[string]int{
			"FROM conflict_keys": 1,
			"(SELECT groupUniqArray(event_key) FROM conflict_keys) AS conflict_key_set,": 1,
			"FROM selected_rows": 1,
			"(SELECT (groupArrayIf((tenant_lo, event_id), tenant_lo = tenant_hi), groupArrayIf(event_id, tenant_lo != tenant_hi))\n\tFROM selected_rows) AS selected_keys,": 1,
			"AND event_key IN (SELECT reinterpretAsUInt128(sipHash128(event_id)) FROM candidate_event_ids)\n\t\tWHERE ingested_at <= snapshot_at":                           1,
		} {
			if got := strings.Count(query, fragment); got != want {
				t.Errorf("%s page query has %d of %q, want %d", name, got, fragment, want)
			}
		}
	}
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "infra", "clickhouse", "migrations", "035_log_page_event_key.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"access_event_query_index_state_v1", "security_event_query_index_state_v1"} {
		for _, statement := range []string{
			"ALTER TABLE " + table + "\n    ADD COLUMN IF NOT EXISTS event_key UInt128 MATERIALIZED reinterpretAsUInt128(sipHash128(event_id));",
			"ALTER TABLE " + table + " MATERIALIZE COLUMN event_key;",
		} {
			if !strings.Contains(string(contents), statement) {
				t.Errorf("migration 035 is missing %q", statement)
			}
		}
	}
}
