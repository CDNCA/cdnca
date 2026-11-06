package migrations

import (
	"strings"
	"testing"
)

// Migration 643 (predecessor 642_market_local_labels): the retention
// cleanup role may delete expired probe_dnspup_plugin_requests rows, and only
// those; edge_health gets a probe type (tcping default / https). Every number
// the predecessor guard touches is here.
func TestProbeDNSPupFollowup643Contract(t *testing.T) {
	read := func(direction string) string {
		body, err := FS.ReadFile("643_probe_dnspup_followup." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("up"), read("down")
	for _, fragment := range []string{
		"ERRCODE='P6430'", "migration_id='642_market_local_labels'",
		"(SELECT count(*) FROM schema_migrations) <> 642", "(SELECT max(version) FROM schema_migrations) <> 642",
		"IF NOT OLD.expires_at < transaction_timestamp() THEN", "ERRCODE='P6432'",
		"BEFORE DELETE ON probe_dnspup_plugin_requests FOR EACH ROW\n    WHEN (current_user = 'cdnca_retention_cleanup')",
		"GRANT SELECT, DELETE ON probe_dnspup_plugin_requests TO cdnca_retention_cleanup",
		"ALTER TABLE probe_dnspup_purposes ADD COLUMN probe_type text;",
		"UPDATE probe_dnspup_purposes SET probe_type = 'tcping' WHERE purpose = 'edge_health';",
		"CASE WHEN purpose = 'edge_health' THEN probe_type IN ('tcping', 'https') ELSE probe_type IS NULL END",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("643 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"ERRCODE='P6431'", "migration_id='643_probe_dnspup_followup'", "(SELECT count(*) FROM schema_migrations) <> 643",
		"REVOKE SELECT, DELETE ON probe_dnspup_plugin_requests FROM cdnca_retention_cleanup",
		"DROP TRIGGER probe_dnspup_plugin_requests_retention_643 ON probe_dnspup_plugin_requests",
		"DROP FUNCTION guard_retention_delete_probe_request_643()",
		"ALTER TABLE probe_dnspup_purposes DROP COLUMN probe_type;",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("643 down missing %q", fragment)
		}
	}
	// The only data change is the edge_health backfill above.
	if strings.Count(up, "UPDATE ") != 1 {
		t.Errorf("643 up must update only the edge_health probe type")
	}
	for _, forbidden := range []string{"DELETE FROM", "DROP TABLE"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("643 up must not contain %q", forbidden)
		}
	}
}
