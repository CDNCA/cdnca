package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 355 (per-site quick block overrides) is a
// placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration355Version         = 355
	migration355ID              = "355_site_quick_block_overrides"
	migration355PreviousID      = "354_edge_site_objects"
	migration355PreviousUpSHA   = "06b5e447a616e274de5bbe543c912dbe19d59b95ce029e6aba73cab40ae42ff4"
	migration355PreviousDownSHA = "d4c3c472ce1bd27ecd9e8c20c3ce7c946a080898e004c64326dc0521e7e1c4c1"
	migration355UpSHA           = "907199b211564f0dfd565251048151c164bce43679aef7d7b223e754961e9e4d"
	migration355DownSHA         = "f320bb5d52d5e56b7da375d0f3a392b8893e5caa0b22c53a5a01222279eb16a7"
)

func TestSiteQuickBlockOverrides355Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration355ID + ".up.sql", migration355UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration355Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration355Version-1),
			"migration_id='" + migration355PreviousID + "'", migration355PreviousUpSHA, migration355PreviousDownSHA,
			"ERRCODE='P3550'", "CREATE TABLE site_quick_block_overrides", "override <> '{}'::jsonb",
			"REFERENCES sites(scope_id, id) ON DELETE CASCADE", "CREATE TABLE site_quick_block_write_requests",
		}},
		{migration355ID + ".down.sql", migration355DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration355Version),
			"migration_id='" + migration355ID + "'", "ERRCODE='P3551'",
			"DROP TABLE site_quick_block_write_requests", "DROP TABLE site_quick_block_overrides",
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
