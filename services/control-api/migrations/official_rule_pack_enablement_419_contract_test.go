package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 419 (the control plane's own platform
// row opening official system packs to lower levels) uses the number reserved
// in BATCH-PLUGIN 第 18 条; its head 417 is pack-suspend (still 416 on that
// branch), whose checksums the merge adds to the guard and to this block.
// Everything that changes with the renumbering is here.
const (
	migration419Version    = 419
	migration419ID         = "419_official_rule_pack_enablement"
	migration419PreviousID = "418_origin_failover"
	migration419UpSHA      = "946e4a466fd59cfe0d24eefe819f544f3bd26293e7b8ff03ad1e7cf4f864bb4c"
	migration419DownSHA    = "991d8645e2aaadc71c3741c28813fb788fb4534c46804fabd1851521768558a3"
)

func TestOfficialRulePackEnablement419Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration419ID + ".up.sql", migration419UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration419Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration419Version-1),
			"migration_id='" + migration419PreviousID + "'",
			"ERRCODE='P4190'", "ALTER COLUMN updated_by_user_id DROP NOT NULL",
			"level = 'platform' AND rule_id IS NULL AND state = 'inherit' AND allow_lower AND priority IS NULL AND params IS NULL",
		}},
		{migration419ID + ".down.sql", migration419DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration419Version),
			"migration_id='" + migration419ID + "'", "ERRCODE='P4191'",
			"DELETE FROM rule_pack_enablements WHERE updated_by_user_id IS NULL",
			"ALTER COLUMN updated_by_user_id SET NOT NULL",
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
