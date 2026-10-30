package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 367 (PA-16 IP intelligence updates) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration367Version         = 367
	migration367ID              = "367_ip_intel_updates"
	migration367PreviousID      = "366_aggregated_edge_schedule"
	migration367PreviousUpSHA   = "27ea5f67dd2fdf1b5d1e224021832c5401266c1223fcca08324f1f83392d1b1d"
	migration367PreviousDownSHA = "99155af5c2dcc842ca8faa42770ccf8b2cddd212ece7b1145be983f79181da74"
	migration367UpSHA           = "955b1067c671e95b8936a8104fca76c2f8915fbcba4c461392a097e1047fe515"
	migration367DownSHA         = "7996a514fc7658985bb94fbec64b504b5a24b3192ab5f9c07743d22e0fa9f8b5"
)

func TestIPIntelUpdates367Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration367ID + ".up.sql", migration367UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration367Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration367Version-1),
			"migration_id='" + migration367PreviousID + "'", migration367PreviousUpSHA, migration367PreviousDownSHA,
			"ERRCODE='P3670'", "CREATE TABLE ip_intel_update_settings", "CREATE TABLE ip_intel_update_state",
			"CREATE TABLE ip_intel_update_write_requests", "artifact_catalog_entries_origin_367_ck",
			"requires_feature = 'module.ipintel.dnspup'", "'system.ip_intel_updates.manage'",
			"REVOKE ALL ON ip_intel_update_settings", "TO cdnca_control_app, cdnca_control_runtime",
		}},
		{migration367ID + ".down.sql", migration367DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration367Version),
			"migration_id='" + migration367ID + "'", "ERRCODE='P3671'", "ERRCODE='P3672'",
			"DROP TABLE ip_intel_update_settings", "DROP COLUMN origin",
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
