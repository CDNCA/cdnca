package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 361 is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration361Version         = 361
	migration361ID              = "361_audit_unified_fields"
	migration361PreviousID      = "360_theme_packages"
	migration361PreviousUpSHA   = "7f508678b3f75627c6f0c7e7e9237bfc8e6d610cd70e3c834a7d1f7b649f4a3d"
	migration361PreviousDownSHA = "601053b7cf96761a25422bb1d6a8813833c0d24c6cd3eb4cc29e958964d82289"
	migration361UpSHA           = "328119e6a5097148319fee0638682cf86e98c3ab57a8e3253a47c16ef6f9ec21"
	migration361DownSHA         = "f5a6d342b089da22c413305dcd863bdc893548713c53b361b016f9f32afffc24"
)

func TestAuditUnifiedFields361Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration361ID + ".up.sql", migration361UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration361Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration361Version-1),
			"migration_id='" + migration361PreviousID + "'", migration361PreviousUpSHA, migration361PreviousDownSHA,
			"ERRCODE='P3610'", "ERRCODE='P3612'",
			"ADD COLUMN category text NOT NULL DEFAULT 'other'",
			"ADD COLUMN actor_kind text NOT NULL DEFAULT 'system'",
			"ADD COLUMN source_ip text NOT NULL DEFAULT ''",
			"ADD COLUMN changes jsonb NOT NULL DEFAULT '[]'::jsonb",
			"CREATE FUNCTION guard_audit_event_archive_insert_361()",
			"DROP TRIGGER audit_event_archive_insert_331 ON audit_event_archive",
			"REVOKE ALL ON FUNCTION guard_audit_event_archive_insert_361() FROM PUBLIC",
			"CREATE FUNCTION guard_audit_event_archive_purge_361()", "ERRCODE='P3614'",
			"DROP TRIGGER audit_event_archive_immutable_331 ON audit_event_archive",
			"GRANT DELETE ON audit_event_archive TO cdnca_retention_cleanup",
		}},
		{migration361ID + ".down.sql", migration361DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration361Version),
			"migration_id='" + migration361ID + "'", "ERRCODE='P3611'", "ERRCODE='P3613'",
			"EXECUTE FUNCTION guard_audit_event_archive_insert_331()",
			"DROP FUNCTION guard_audit_event_archive_insert_361()",
			"DROP FUNCTION guard_audit_event_archive_purge_361()",
			"REVOKE DELETE ON audit_event_archive FROM cdnca_retention_cleanup",
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
