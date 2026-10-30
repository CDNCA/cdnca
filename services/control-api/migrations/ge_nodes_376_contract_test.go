package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 376 is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration376Version         = 376
	migration376ID              = "376_ge_nodes"
	migration376PreviousID      = "375_aggregated_edge_sync"
	migration376PreviousUpSHA   = "d2308d69879b56ad3e8c9f7e949040be172ee0a885c7e35ae82e7a53f36eaabf"
	migration376PreviousDownSHA = "aa57e0f7c659acf870036af06900e12be5325abaf735b22c390aa36bdbb90071"
	migration376UpSHA           = "0ad20b16426922d6431242432f2f849377f08a1ba877d5cb789549c45844f36b"
	migration376DownSHA         = "226f0e4861f84b421af0549207d09998e888abfd6e0dfe4eb5d9f4298fba4ae9"
)

func TestGENodes376Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration376ID + ".up.sql", migration376UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration376Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration376Version-1),
			"migration_id='" + migration376PreviousID + "'", migration376PreviousUpSHA, migration376PreviousDownSHA,
			"ERRCODE='P3760'",
			"node_line_groups_failover_mode_376_check", "node_line_group_revisions_failover_mode_376_check",
			"CREATE TABLE cname_carrier_line_records", "'dns_la', 'custom_http')",
			"'config_sync', 'external_probe'", "CREATE TABLE node_ssh_install_jobs",
		}},
		{migration376ID + ".down.sql", migration376DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration376Version),
			"migration_id='" + migration376ID + "'", "ERRCODE='P3761'",
			"node_line_groups_failover_mode_234_check", "DROP TABLE cname_carrier_line_records", "DROP TABLE node_ssh_install_jobs",
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
