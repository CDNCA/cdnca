package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Audit archive. Every number the merge renumbering touches is here.
const (
	auditArchiveVersion        = 331
	auditArchiveID             = "331_audit_event_archive"
	auditArchivePreviousID     = "330_traffic_package_cycle_deductions"
	auditArchivePreviousUpSHA  = "86501d58b9f46cc864e4a515ace7018be8cb818259d2115a1fb08b12ea12b5d9"
	auditArchivePreviousDownSH = "b57a58a9da12689fac74933a55e33da098701148928705807a1790da957a15ee"
	auditArchiveUpSHA          = "1af7fdf12733a8ddb1d322033c71e756d9ec13e18ff35acb10b7c3fe65715831"
	auditArchiveDownSHA        = "5d9b52ec22684e388f4faff0defa55e6cc10f2796a2ec77c5eae5fe8b32c18df"
)

func TestAuditEventArchive331Contract(t *testing.T) {
	previous := auditArchiveVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{auditArchiveID + ".up.sql", auditArchiveUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + auditArchivePreviousID + "'",
			"checksum_sha256='" + auditArchivePreviousUpSHA + "'",
			"down_checksum_sha256='" + auditArchivePreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", auditArchiveVersion),
			// The four referencing columns that had no index.
			"ON cache_operation_target_results(audit_event_id)",
			"ON cname_allocation_requests(audit_event_id)",
			"ON notification_delivery_command_receipts_108(audit_event_id)",
			"ON notification_delivery_facts_108(audit_event_id)",
			// Everyone but the cleanup role keeps an append-only audit_events.
			"WHEN (current_user <> 'cdnca_retention_cleanup') EXECUTE FUNCTION prevent_audit_event_mutation()",
			"constraint_row.confrelid = %L::regclass",
		}},
		{auditArchiveID + ".down.sql", auditArchiveDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", auditArchiveVersion),
			"migration_id='" + auditArchiveID + "'",
			"IF EXISTS (SELECT 1 FROM audit_chain_checkpoints) THEN",
			"BEFORE UPDATE OR DELETE ON audit_events",
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
