package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 330 (traffic package cycle deductions) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration330Version         = 330
	migration330ID              = "330_traffic_package_cycle_deductions"
	migration330PreviousID      = "329_ip_intel_node_distribution"
	migration330PreviousUpSHA   = "478749ae18f6af81b650f2c2f50845cc7ea7e2f201a70aeb3d1189622c715187"
	migration330PreviousDownSHA = "65b1265253a15eccf0d664ac868cf7161a49b38be38d499cf5559d6781b92d07"
	migration330UpSHA           = "86501d58b9f46cc864e4a515ace7018be8cb818259d2115a1fb08b12ea12b5d9"
	migration330DownSHA         = "b57a58a9da12689fac74933a55e33da098701148928705807a1790da957a15ee"
)

func TestTrafficPackageCycleDeductions330Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration330ID + ".up.sql", migration330UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration330Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration330Version-1),
			"migration_id='" + migration330PreviousID + "'", migration330PreviousUpSHA, migration330PreviousDownSHA,
			"ERRCODE='P3300'", "CREATE TABLE traffic_package_cycle_deductions",
			"PRIMARY KEY (tenant_scope_id, subscription_id, period_key, sequence)",
			"covered_after_bytes <= target_overage_bytes", "WHERE status IN ('active', 'exhausted')",
		}},
		{migration330ID + ".down.sql", migration330DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration330Version),
			"migration_id='" + migration330ID + "'", "ERRCODE='P3301'", "ERRCODE='P3302'",
			"DROP TABLE traffic_package_cycle_deductions",
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
