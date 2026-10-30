package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 342 (ADR-0003 cleanup debt, epochs, serving gate,
// 063 backfill) is a placeholder number: the merge renumbers it after the head
// it lands on. Everything that changes with the renumbering is in this block.
const (
	migration342Version         = 342
	migration342ID              = "342_acme_http01_cleanup_debt"
	migration342PreviousID      = "341_l4_guard_rules"
	migration342PreviousUpSHA   = "986ce0399908def5abb7d0805c8c2f11767e1180a9d2957b7ee4c89db371d8cb"
	migration342PreviousDownSHA = "746551be8cc0506711a82f89053f715780f2667f5e921836943d31dc8e3f547c"
	migration342UpSHA           = "7d99900ceb9f9955c3fef1589c16a0f0d427db3c40e2af207229d9b0a12d9520"
	migration342DownSHA         = "36dae24e16005edbcf884290fe51558bb1ad99cc26f1c8aca3a02153fde4145b"
)

func TestACMEHTTP01CleanupDebt342Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration342ID + ".up.sql", migration342UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration342Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration342Version-1),
			"migration_id='" + migration342PreviousID + "'", migration342PreviousUpSHA, migration342PreviousDownSHA,
			"ERRCODE='P3420'", "CREATE TABLE acme_http01_node_overlay_cleanup_debts",
			"CREATE TABLE acme_http01_node_overlay_cleanup_debt_events",
			"CREATE TABLE acme_http01_node_overlay_generation_coverages",
			"coverage_kind IN ('required', 'cleanup_debt')", "purpose IN ('apply', 'cleanup_only')",
			"CREATE VIEW acme_http01_node_overlay_cleanup_debt_states",
			"CREATE FUNCTION acme_http01_site_node_serving_blocked", "CREATE FUNCTION acme_http01_backfill_063",
			"SELECT acme_http01_backfill_063();", "hashtextextended('acme-http01-overlay', 0)",
		}},
		{migration342ID + ".down.sql", migration342DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration342Version),
			"migration_id='" + migration342ID + "'", "ERRCODE='P3429'", "ERRCODE='P0001'",
			"DROP TABLE acme_http01_node_overlay_cleanup_debts",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
