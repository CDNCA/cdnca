package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 504: a line group's L2 configuration is an L2
// topology configuration (l2_topology_configs), not another line group.
// Local placeholder 497, renumbered 504 at merge (predecessor 503).
const (
	migration504Version         = 504
	migration504PreviousVersion = 503
	migration504ID              = "504_line_group_l2_topology_config"
	migration504PreviousID      = "503_site_sync_status_derived"
	migration504PreviousUpSHA   = "6d01563e0763f0f33da5b9592cc49e5a0695f88bb67860f4ee3f7c62add8accb"
	migration504PreviousDownSHA = "1a29a4bb749ebcb41be720c00ab010d8b2c5deaff622a39369b656cebeb3e0e1"
	migration504UpSHA           = "8cde62e682fafe211948d4e8e36939cb263d1302d562a30b3def7cf328bf4188"
	migration504DownSHA         = "6305b76f82ed1dcda54f5be0d56943a94cf0a6e21aa715a6eaa426d689ba1291"
)

func TestLineGroupL2TopologyConfig504Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration504ID + ".up.sql", migration504UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration504PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration504PreviousVersion),
			"migration_id='" + migration504PreviousID + "'", migration504PreviousUpSHA, migration504PreviousDownSHA,
			"ERRCODE='P5040'", "DROP FUNCTION assert_node_line_group_reference_234()",
			"DROP CONSTRAINT node_line_groups_l2_scope_234_fk", "DROP CONSTRAINT node_line_group_revisions_l2_scope_234_fk",
			"REFERENCES l2_topology_configs(tenant_scope_id, id)", "UPDATE node_line_groups SET l2_config_id = NULL",
			"UPDATE node_line_group_revisions SET l2_config_id = NULL", "ERRCODE = 'P5043'", "ERRCODE = 'P5044'",
			"advance_edge_configuration_scope_revision(", "ON l2_topology_nodes",
		}},
		{migration504ID + ".down.sql", migration504DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration504Version),
			"migration_id='" + migration504ID + "'", "ERRCODE='P5041'", "ERRCODE='P5042'",
			"REFERENCES node_line_groups(tenant_scope_id, id)", "CREATE FUNCTION assert_node_line_group_reference_234()",
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
