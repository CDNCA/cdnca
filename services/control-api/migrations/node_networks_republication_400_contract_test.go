package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 400 (system republication trigger
// node_networks) is a placeholder number (BATCH-PLUGIN 第 16 条): the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is here.
const (
	migration400Version         = 400
	migration400ID              = "400_node_networks_republication"
	migration400PreviousID      = "399_security_activation_v2_root"
	migration400PreviousUpSHA   = "10ed624dec56751600ff30cc869a5c2215845bb6b3e6770a7e8165e4a9d37b7e"
	migration400PreviousDownSHA = "a8885fa8fb4679ce1dd62dfc0a414d48d6c64a0620471dda00f8e32b2fb9399f"
	migration400UpSHA           = "7dfc53b4b0f54af75c347de956477a80bbc7df189f086e98c2c25cbe98f6db61"
	migration400DownSHA         = "9a52560e0f8b09a9b9c8d962a63117ed85015b49d4a8db76d3ebf9c7d5635dd5"
)

func TestNodeNetworksRepublication400Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration400ID + ".up.sql", migration400UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration400Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration400Version-1),
			"migration_id='" + migration400PreviousID + "'", migration400PreviousUpSHA, migration400PreviousDownSHA,
			"ERRCODE='P4000'", "CREATE TABLE edge_node_network_marks",
			"'theme_activation', 'account_suspension', 'node_networks']::text[]",
			"'module_entitlement', 'account_suspension', 'node_networks'));", "BETWEEN 1 AND 12",
			"'challenge_delivery', 'module_entitlement', 'node_networks')),", "'node.networks_changed'",
			"reason = 'node_networks_changed'",
		}},
		{migration400ID + ".down.sql", migration400DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration400Version),
			"migration_id='" + migration400ID + "'", "ERRCODE='P4001'", "ERRCODE='P4002'",
			"DROP TABLE edge_node_network_marks", "'theme_activation', 'account_suspension']::text[]",
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
