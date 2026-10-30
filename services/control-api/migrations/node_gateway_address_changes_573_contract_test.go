package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 573 (fix-nodegw: 节点设置「更换主控连接地址」) is a placeholder
// number; the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is here.
const (
	migration573Version         = 573
	migration573PreviousVersion = 572
	migration573PreviousID      = "572_aggregated_edge_migrate_restore"
	migration573PreviousUpSHA   = "4b562a0e35cc7450eb0181d5c7e797eafe785fdef4fb1536ba62f44feadc9d67"
	migration573PreviousDownSHA = "e3cc084098d0f31afdd8667cd445ed535c8e381d7208b1db5578ba238c05d2d9"
	migration573ID              = "573_node_gateway_address_changes"
)

func TestNodeGatewayAddressChanges573Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration573ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration573PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration573PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration573PreviousVersion),
			"migration_id='" + migration573PreviousID + "'",
			"checksum_sha256='" + migration573PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration573PreviousDownSHA + "'",
			"ERRCODE='P5730'", "CREATE TABLE node_gateway_address_changes",
			"CREATE TABLE node_gateway_address_node_revisions", "CREATE TABLE node_gateway_address_change_nodes",
			"WHERE state IN ('pending', 'delivered', 'probing')",
		}},
		{migration573ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration573Version),
			"migration_id='" + migration573ID + "'", "ERRCODE='P5731'", "ERRCODE='P5732'",
			"DROP TABLE node_gateway_address_change_nodes",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration573PreviousUpSHA, ".down.sql": migration573PreviousDownSHA} {
		raw, err := FS.ReadFile(migration573PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration573PreviousID, suffix, got, want)
		}
	}
}
