package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 337 (HTTP-01 node generations) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration337Version         = 337
	migration337ID              = "337_acme_http01_node_generations"
	migration337PreviousID      = "336_cc_auto_switch_notifications"
	migration337PreviousUpSHA   = "6e34c6db1ba2d447b357d240e9bfc490b100f61e534062043d6a4fdcaeb7873e"
	migration337PreviousDownSHA = "4796a65eba5dfc3787e7c9e8231f792e6ebbe52592b806af7bf17013b8ef7067"
	migration337UpSHA           = "b1623133b8240241628bea733cf6c19564e7aeaeab008336d95c3b4af5f9ef8a"
	migration337DownSHA         = "da3a494d77514017a42aae878b2460f86c4c48092d442aaf15605b4158457659"
)

func TestACMEHTTP01NodeGenerations337Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration337ID + ".up.sql", migration337UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration337Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration337Version-1),
			"migration_id='" + migration337PreviousID + "'", migration337PreviousUpSHA, migration337PreviousDownSHA,
			"ERRCODE='P3370'", "CREATE TABLE acme_http01_node_challenges", "CREATE TABLE acme_http01_node_overlay_generations",
			"CREATE TABLE acme_http01_node_overlay_states", "CREATE TABLE acme_http01_node_overlay_deliveries",
			"CHECK (latest_healthy_generation <= current_generation)", "acme_http01_node_generation_digest_337",
			"DEFERRABLE INITIALLY DEFERRED",
		}},
		{migration337ID + ".down.sql", migration337DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration337Version),
			"migration_id='" + migration337ID + "'", "ERRCODE='P3377'", "ERRCODE='P3378'",
			"DROP TABLE acme_http01_node_challenges",
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
