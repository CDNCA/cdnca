package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 411 (AutoDefenseCommand delivery and receipts per
// node) is a placeholder number (BATCH-PLUGIN 第 16 条): the merge renumbers
// it. Everything that changes with the renumbering is here.
const (
	migration411Version         = 411
	migration411ID              = "411_autodefense_node_snapshots"
	migration411PreviousVersion = 410
	migration411PreviousID      = "410_autodefense_baseline_drift"
	migration411PreviousUpSHA   = "12e3716efa11045662977648da7b67910e01e633ce2e6acbeb880f7cdf2de28b"
	migration411PreviousDownSHA = "79411f1082cef12ebc7d14aed75fb1efc675df0bee3c42b5823ded04bb1d6ab3"
	migration411UpSHA           = "0091103ea84713da66b4db77dc1026d2ceb09bfe4b57a6109a1d3e1cbdb3fc50"
	migration411DownSHA         = "4a88857d1391067a7ff2117e91eae8d93184130a188013a1a6e4bf6c3b747415"
)

func TestAutoDefenseNodeSnapshots411Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration411ID + ".up.sql", migration411UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration411PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration411PreviousVersion),
			"migration_id='" + migration411PreviousID + "'", migration411PreviousUpSHA, migration411PreviousDownSHA,
			"ERRCODE='P4110'", "CREATE TABLE autodefense_node_snapshots", "'not_supported'",
		}},
		{migration411ID + ".down.sql", migration411DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration411Version),
			"migration_id='" + migration411ID + "'", "ERRCODE='P4111'", "DROP TABLE autodefense_node_snapshots",
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
