package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 461 (ban / site drop list truncation warnings) is a
// placeholder number; the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration461Version         = 461
	migration461ID              = "461_ban_list_truncation"
	migration461PreviousID      = "460_attack_escalation"
	migration461PreviousUpSHA   = "1df7430b58c0d00752bac88118cfb40c49171b93f323d3d5ca6b57e3debda662"
	migration461PreviousDownSHA = "5476994323e7aaeae25b23915c6b6e72e01762072f3df6173c91c8e0b71668f5"
	migration461UpSHA           = "382e5e63754dcd34c767fb8654ac7620ca60e0481a506bf69474562c2863e6a6"
	migration461DownSHA         = "79e1d9f8840b9a0e79f16b11fce133c62b39ddc379beb42b1e172492e7d2380b"
)

func TestBanListTruncation461Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration461ID + ".up.sql", migration461UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration461Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration461Version-1),
			"migration_id='" + migration461PreviousID + "'", migration461PreviousUpSHA, migration461PreviousDownSHA,
			"ERRCODE='P4610'", "'node.security.list_truncated'", "'node.security.list_truncated.zh-cn'", "'list_truncated'",
		}},
		{migration461ID + ".down.sql", migration461DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration461Version),
			"migration_id='" + migration461ID + "'", "ERRCODE='P4611'", "ERRCODE='P4612'",
			"'node.security.list_truncated.zh-cn'",
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
