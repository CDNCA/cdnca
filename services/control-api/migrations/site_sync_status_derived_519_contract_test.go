package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 503 (PJ-C02): sites.sync_status dropped, derived by
// site_sync_status_503 from the site's latest automatic publication. Local
// placeholder 497, renumbered 503 at merge (predecessor 502).
const (
	migration503Version       = 503
	migration503ID            = "503_site_sync_status_derived"
	migration503PreviousID    = "502_notification_event_subjects"
	migration503UpSHA         = "6d01563e0763f0f33da5b9592cc49e5a0695f88bb67860f4ee3f7c62add8accb"
	migration503DownSHA       = "1a29a4bb749ebcb41be720c00ab010d8b2c5deaff622a39369b656cebeb3e0e1"
	migration503PreviousUpSHA = migration502UpSHA
)

func TestSiteSyncStatusDerived503Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
		forbidden []string
	}{
		{migration503ID + ".up.sql", migration503UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration503Version-1),
			"migration_id='" + migration503PreviousID + "'", migration503PreviousUpSHA, migration502DownSHA,
			"ERRCODE='P5030'", "ERRCODE='P5031'", "ALTER TABLE sites DROP COLUMN sync_status",
			"CREATE FUNCTION site_sync_status_503(scope_id uuid, site_id uuid)",
			"WHEN 'succeeded' THEN 'synced' WHEN 'failed' THEN 'failed' ELSE 'pending'",
			"request_row.source_kind='site' AND request_row.source_resource_id=$2",
			"'cdnca:dns-reconcile:site-authority:v2'",
		}, []string{"checked_site.sync_status"}},
		{migration503ID + ".down.sql", migration503DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration503Version),
			"migration_id='" + migration503ID + "'", "ERRCODE='P5032'", "ERRCODE='P5033'",
			"ALTER TABLE sites ADD COLUMN sync_status", "'cdnca:dns-reconcile:site-authority:v1'",
			"checked_site.sync_status, checked_site.is_default", "DROP FUNCTION site_sync_status_503(uuid, uuid)",
		}, nil},
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
		for _, forbidden := range script.forbidden {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s still has %q", script.name, forbidden)
			}
		}
	}
}
