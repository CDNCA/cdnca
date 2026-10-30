package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 301 is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration301Version         = 301
	migration301ID              = "301_line_group_publication_sync_hold"
	migration301PreviousID      = "300_l4_new_connection_rate"
	migration301PreviousUpSHA   = "57c497adfbc4c2bc9d1cf87c872332bc6d919614dc33132868fe8a00cdbef250"
	migration301PreviousDownSHA = "fb2987d6d82d8db1c8e19607d71fbbdfc872e88d7575a0fbdcc9a2604d9a279a"
	migration301UpSHA           = "18f6165f855411e1de1799454ec7e8c22245cdf292ddcc40b13d921ff11092f8"
	migration301DownSHA         = "17463b2c338ce34c72c1e096c0ef5ac92eda769d7d4020ca343f1d76f8443248"
)

func TestLineGroupPublicationSyncHold301Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration301ID + ".up.sql", migration301UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration301Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration301Version-1),
			"migration_id='" + migration301PreviousID + "'", migration301PreviousUpSHA, migration301PreviousDownSHA,
			"ERRCODE='P3010'", "'line_group', 'node_sync'", "'line_group.nodes_changed', 'node.sync_retry'",
			"source_kind IN ('site', 'line_group', 'node_sync') AND publish_intent_id IS NULL",
			"CHECK (source IN ('availability_monitor', 'auto_disable', 'config_sync'))",
		}},
		{migration301ID + ".down.sql", migration301DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration301Version),
			"migration_id='" + migration301ID + "'", "ERRCODE='P3011'",
			"source_kind IN ('line_group', 'node_sync')", "WHERE source = 'config_sync'",
			"CHECK (source_kind IN ('site', 'l4'))", "CHECK (reason = 'resource_mutation')",
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
