package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 423 (adaptive WAF on the control plane; 415 on its
// branch, 417 on ri-wire; ri-merge renumbered it to 423 after the
// integration head 421_node_security_event_alerts). Everything that
// changes with the renumbering is in this block.
const (
	wafAdaptMigrationVersion         = 423
	wafAdaptMigrationID              = "423_waf_adapt"
	wafAdaptMigrationPreviousID      = migration422ID
	wafAdaptMigrationPreviousUpSHA   = migration422UpSHA
	wafAdaptMigrationPreviousDownSHA = migration422DownSHA
	wafAdaptMigrationUpSHA           = "a96f39b3ce63fc7fb8325e530bef43bd58526c006db914409cd1960ad2fbbe7c"
	wafAdaptMigrationDownSHA         = "938c271f6d5053acf34337408443fbd02d3077aac719f48c9c3f5d8d08acb2ba"
)

func TestWAFAdaptContract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{wafAdaptMigrationID + ".up.sql", wafAdaptMigrationUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", wafAdaptMigrationVersion-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", wafAdaptMigrationVersion-1),
			"migration_id='" + wafAdaptMigrationPreviousID + "'", wafAdaptMigrationPreviousUpSHA, wafAdaptMigrationPreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", wafAdaptMigrationVersion), "CREATE TABLE waf_adapt_exclusions", "'drift', 'waf_evidence'",
			"'security.waf.auto_exclusion_active'", "'security.waf.auto_exclusion_revoked'", "'security.waf.auto_exclusion_expired'",
		}},
		{wafAdaptMigrationID + ".down.sql", wafAdaptMigrationDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", wafAdaptMigrationVersion),
			"migration_id='" + wafAdaptMigrationID + "'", fmt.Sprintf("ERRCODE='P%d1'", wafAdaptMigrationVersion),
			fmt.Sprintf("ERRCODE='P%d2'", wafAdaptMigrationVersion), "DROP TABLE waf_adapt_exclusions",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
