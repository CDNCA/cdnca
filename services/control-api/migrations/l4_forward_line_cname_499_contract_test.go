package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 499: a stream's own CNAME domain / mode and
// line (region, line group, backup group). renumbered 491→499 at merge; the
// guard pins 498_tenant_order_records_read_only.
const (
	migration499Version         = 499
	migration499PreviousVersion = 498
	migration499ID              = "499_l4_forward_line_cname"
	migration499PreviousID      = "498_tenant_order_records_read_only"
	migration499PreviousUpSHA   = migration498UpSHA
	migration499PreviousDownSHA = migration498DownSHA
	migration499UpSHA           = "8e2a262111f086a12ed9477dffe2b342c047a521c5fd219be3ffd845e0b5cc15"
	migration499DownSHA         = "f670e99b6f6387dde2cd07fb3190da658f2f553a5178313f82c44596a887c133"
)

func TestL4ForwardLineCNAME499Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration499ID + ".up.sql", migration499UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration499PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration499PreviousVersion),
			"migration_id='" + migration499PreviousID + "'", migration499PreviousUpSHA, migration499PreviousDownSHA,
			"ERRCODE='P4990'", "ADD COLUMN cname_domain text", "ADD COLUMN cname_mode text", "ADD COLUMN region_id uuid",
			"ADD COLUMN node_group_id uuid", "ADD COLUMN backup_node_group_id uuid", "l4_forwards_line_cname_499",
		}},
		{migration499ID + ".down.sql", migration499DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration499Version),
			"migration_id='" + migration499ID + "'", "ERRCODE='P4991'", "ERRCODE='P4992'", "DROP COLUMN cname_domain",
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
