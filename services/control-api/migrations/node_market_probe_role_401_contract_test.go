package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 401 (node_presence.market_probe_role) is a
// placeholder number; everything the renumbering changes is in this block.
const (
	migration401Version         = 401
	migration401ID              = "401_node_market_probe_role"
	migration401PreviousID      = "400_node_networks_republication"
	migration401PreviousUpSHA   = "7dfc53b4b0f54af75c347de956477a80bbc7df189f086e98c2c25cbe98f6db61"
	migration401PreviousDownSHA = "9a52560e0f8b09a9b9c8d962a63117ed85015b49d4a8db76d3ebf9c7d5635dd5"
	migration401UpSHA           = "942285d0f81c261d36056e8cc84c4545554bbd062c229f9038ab68d14a26efce"
	migration401DownSHA         = "dbb2e5d211afb1e0156bfa3d6ed8f52e0c829e8239c66979f743addfd85140cb"
)

func TestNodeMarketProbeRole401Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration401ID + ".up.sql", migration401UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration401Version-1),
			"migration_id='" + migration401PreviousID + "'", migration401PreviousUpSHA, migration401PreviousDownSHA,
			"ERRCODE='P4010'", "node_presence_market_probe_role_401_check",
			"market_probe_role IN ('probe_only', 'join_market', 'disabled')",
		}},
		{migration401ID + ".down.sql", migration401DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration401Version),
			"migration_id='" + migration401ID + "'", "ERRCODE='P4011'", "DROP COLUMN market_probe_role",
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
