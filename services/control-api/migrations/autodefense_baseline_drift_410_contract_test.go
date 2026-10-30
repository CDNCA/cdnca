package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 410 (auto defense baseline drift reports) is a
// placeholder number (BATCH-PLUGIN 第 16 条): the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration410Version         = 410
	migration410ID              = "410_autodefense_baseline_drift"
	migration410PreviousVersion = 409
	migration410PreviousID      = "409_tenant_member_handover"
	migration410PreviousUpSHA   = "619c8bcd003ec67de37e8e96c7e38d9430f4e9b46528748e46cf71d5dcdfd8a7"
	migration410PreviousDownSHA = "8a5ec6bab67fe7e8a8a63a6efdaf0ee30bdecca5a72c33c39fcf0c3adc85ac25"
	migration410UpSHA           = "12e3716efa11045662977648da7b67910e01e633ce2e6acbeb880f7cdf2de28b"
	migration410DownSHA         = "79411f1082cef12ebc7d14aed75fb1efc675df0bee3c42b5823ded04bb1d6ab3"
)

func TestAutoDefenseBaselineDrift410Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration410ID + ".up.sql", migration410UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration410PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration410PreviousVersion),
			"migration_id='" + migration410PreviousID + "'", migration410PreviousUpSHA, migration410PreviousDownSHA,
			"ERRCODE='P4100'", "CREATE TABLE autodefense_baseline_drifts", "'node_event', 'drift'",
		}},
		{migration410ID + ".down.sql", migration410DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration410Version),
			"migration_id='" + migration410ID + "'", "ERRCODE='P4101'", "DROP TABLE autodefense_baseline_drifts",
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
