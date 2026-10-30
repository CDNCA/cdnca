package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 428 (official plugin module.probe.dnspup),
// guarded on 426 (d13-merge). Everything that changes with the renumbering is
// here.
const (
	migration428Version         = 428
	migration428PreviousVersion = 427
	migration428ID              = "428_dnspup_probe"
	migration428PreviousID      = "427_market_supply_line_groups"
	migration428PreviousUpSHA   = "a108fd06c68a15675aace029e9a278e09c84a1569259d053ef4fcb316f9eb5aa"
	migration428PreviousDownSHA = "0e38dc6344858f9e661065ead129785f3d36da63f5be0177188ddbe0b3c5f784"
	migration428UpSHA           = "7b4bd22bf266163c468bcae6b4ce1399f2028b1b290e82fd448d309db056089a"
	migration428DownSHA         = "3b696105c80aabb235d328931a4d43596f41aa46b9f14e8b2ec030b422737337"
)

func TestDNSPupProbe428Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration428ID + ".up.sql", migration428UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration428PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration428PreviousVersion),
			"migration_id='" + migration428PreviousID + "'", migration428PreviousUpSHA, migration428PreviousDownSHA,
			"ERRCODE='P4280'", "ARRAY['node', 'dnspup', 'controller']", "ARRAY['node', 'dnspup']",
			"'system.probe_dnspup.manage'", "'probe.dnspup.degraded'", "'probe.dnspup.degraded.zh-cn'",
		}},
		{migration428ID + ".down.sql", migration428DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration428Version),
			"migration_id='" + migration428ID + "'", "ERRCODE='P4281'", "ERRCODE='P4282'",
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
