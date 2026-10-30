package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 338 (per-cycle coverage bounds and purchase wake-up)
// is a placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration338Version         = 338
	migration338ID              = "338_traffic_package_coverage_wake"
	migration338PreviousID      = "337_acme_http01_node_generations"
	migration338PreviousUpSHA   = "b1623133b8240241628bea733cf6c19564e7aeaeab008336d95c3b4af5f9ef8a"
	migration338PreviousDownSHA = "da3a494d77514017a42aae878b2460f86c4c48092d442aaf15605b4158457659"
	migration338UpSHA           = "3e612e89e79c7d6e421a2d176ff3c11fe83da6812bdc96fad2c36b23464ad9ed"
	migration338DownSHA         = "361868f603b6970a9ad1069c9f7cce04b57c8fae6da50c52c903f47c1047bd43"
)

func TestTrafficPackageCoverageWake338Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration338ID + ".up.sql", migration338UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration338Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration338Version-1),
			"migration_id='" + migration338PreviousID + "'", migration338PreviousUpSHA, migration338PreviousDownSHA,
			"ERRCODE='P3380'", "ADD COLUMN cycle_starts_at timestamptz",
			"pg_notify('package_traffic_enforcement_wake'", "AFTER INSERT ON traffic_package_grants",
		}},
		{migration338ID + ".down.sql", migration338DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration338Version),
			"migration_id='" + migration338ID + "'", "ERRCODE='P3381'",
			"DROP FUNCTION wake_package_traffic_enforcement_338()", "DROP COLUMN cycle_starts_at",
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
