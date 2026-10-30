package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 405 (WAF observe mode / auto block) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	geWAFMigration405Version         = 405
	geWAFMigration405ID              = "405_waf_policy_settings"
	geWAFMigration405PreviousID      = "404_payment_plugin_reconciliation"
	geWAFMigration405PreviousUpSHA   = "83d1db6e59f5da39d7bb99692fb1b144a7566d1b61c351c9024d07e5617d075c"
	geWAFMigration405PreviousDownSHA = "d3a99945f04d709752864554794211e6ab7e6527154c12d4caf503713391e2f2"
	geWAFMigration405UpSHA           = "5d0a1cdfefe13fb721140a02396c81a5fce019c6355af0e9b5c2f01cbbc4a6d0"
	geWAFMigration405DownSHA         = "f163b0ad8450a6fa06672a052059d97fc393430589b0258218d7e299acd04189"
)

func TestWAFPolicySettings405Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{geWAFMigration405ID + ".up.sql", geWAFMigration405UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration405Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", geWAFMigration405Version-1),
			"migration_id='" + geWAFMigration405PreviousID + "'", geWAFMigration405PreviousUpSHA, geWAFMigration405PreviousDownSHA,
			"ERRCODE='P4050'", "ADD COLUMN waf_settings jsonb", "security_policies_waf_settings_405",
		}},
		{geWAFMigration405ID + ".down.sql", geWAFMigration405DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration405Version),
			"migration_id='" + geWAFMigration405ID + "'", "ERRCODE='P4051'", "ERRCODE='P4052'", "DROP COLUMN waf_settings",
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
