package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 466 is a local placeholder: the merge
// renumbered it to 466 (after 465 cname-retry3). Everything that changes
// with the renumbering is here.
const (
	migration466Version         = 466
	migration466ID              = "466_site_edge_options"
	migration466PreviousID      = "465_package_cname_sync"
	migration466PreviousUpSHA   = "769f707d96643c9ac8d7001c4167ab12d73c3f86cdcd84ccafd58554ea72a61e"
	migration466PreviousDownSHA = "2235ca001a1ded0c1d73ca91d3c58d09b306507e2f545576febbd8226ccc6bc8"
	migration466UpSHA           = "44b2492ac321dc4b2108a10f456e4848fef06aafb7e8311657dcc56a192f043d"
	migration466DownSHA         = "013db3a4cfcb4598f31251dc1e59fec54addb29e7800459ea1848ec932ec46fe"
)

func TestSiteEdgeOptions466Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration466ID + ".up.sql", migration466UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration466Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration466Version-1),
			"migration_id='" + migration466PreviousID + "'", migration466PreviousUpSHA, migration466PreviousDownSHA,
			"ERRCODE='P4660'", "ADD COLUMN acme_passthrough boolean NOT NULL DEFAULT false",
			"ADD COLUMN response_buffering boolean NOT NULL DEFAULT true",
			"ADD COLUMN request_buffering boolean NOT NULL DEFAULT true",
			"CHECK (l2_mode IN ('package', 'off', 'custom'))",
			"((l2_mode = 'custom') = (l2_config_id IS NOT NULL))",
			"ON sites ((true)) WHERE is_default AND deleted_at IS NULL", "ERRCODE = 'P4663'",
		}},
		{migration466ID + ".down.sql", migration466DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration466Version),
			"migration_id='" + migration466ID + "'", "ERRCODE='P4661'", "ERRCODE='P4662'",
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
