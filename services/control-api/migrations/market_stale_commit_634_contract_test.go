package migrations

import (
	"strings"
	"testing"
)

// Migration 634 (on top of 633
// control_db_pool_alerts): a failed security
// activation candidate whose node moved on to a newer ordinary configuration
// counts as recovered, and the leaf records the subscriber revision it
// applied per market site. Down restores the 095 recovery predicate verbatim.
func TestMarketStaleCommit634Contract(t *testing.T) {
	up := readStaleCommit634(t, "up")
	down := readStaleCommit634(t, "down")
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 633", "(SELECT max(version) FROM schema_migrations) <> 633",
		"migration_id='633_control_db_pool_alerts'", "ERRCODE='P6340'",
		"CREATE OR REPLACE FUNCTION security_policy_activation_recovered_095(checked_candidate_id uuid)",
		"AND newer.created_at > deployment.created_at",
		"AND newer.action='apply' AND newer.state IN ('activated','healthy')",
		"AND newer_state.current_config_version_id IS DISTINCT FROM\n                                    apply_pending.candidate_config_version_id",
		"CREATE TABLE market_supply_site_revisions",
		"high_revision bigint NOT NULL CHECK (high_revision >= applied_revision)",
		"PRIMARY KEY (tenant_scope_id, site_id)",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("634 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{"ERRCODE='P6341'", "DROP TABLE market_supply_site_revisions"} {
		if !strings.Contains(down, fragment) {
			t.Errorf("634 down missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE security_policy_activation_candidates"} {
		if strings.Contains(up, forbidden) || strings.Contains(down, forbidden) {
			t.Errorf("634 must not contain %q", forbidden)
		}
	}
	original, err := FS.ReadFile("095_security_activation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	const declaration = "FUNCTION security_policy_activation_recovered_095(checked_candidate_id uuid)"
	want := strings.Replace(sqlFunctionBody(t, string(original), "CREATE "+declaration), "CREATE FUNCTION",
		"CREATE OR REPLACE FUNCTION", 1)
	if got := sqlFunctionBody(t, down, "CREATE OR REPLACE "+declaration); got != want {
		t.Error("634 down does not restore the exact 095 recovery predicate")
	}
	changed := sqlFunctionBody(t, up, "CREATE OR REPLACE "+declaration)
	if changed == want || !strings.HasPrefix(changed, want[:strings.Index(want, "AND rollback_outbox.status='published'")]) {
		t.Error("634 up must only extend the 095 recovery predicate")
	}
}

// readStaleCommit634 reads the 634 script, also under the local test name 631
// (a local copy renumbered for a tree without 631–633: the loader wants contiguous numbers).
func readStaleCommit634(t *testing.T, direction string) string {
	t.Helper()
	for _, name := range []string{"634_market_stale_commit.", "631_market_stale_commit."} {
		if body, err := FS.ReadFile(name + direction + ".sql"); err == nil {
			return string(body)
		}
	}
	t.Fatalf("634 %s script not found", direction)
	return ""
}

func sqlFunctionBody(t *testing.T, script, declaration string) string {
	t.Helper()
	start := strings.Index(script, declaration)
	if start < 0 {
		t.Fatalf("SQL function %q not found", declaration)
	}
	end := strings.Index(script[start:], "\n$$;")
	if end < 0 {
		t.Fatalf("SQL function %q has no terminator", declaration)
	}
	return script[start : start+end+len("\n$$;")]
}
