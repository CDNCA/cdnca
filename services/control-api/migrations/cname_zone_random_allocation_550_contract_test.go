package migrations

import (
	"strings"
	"testing"
)

// Migration 550: CNAME domains marked for random
// allocation. The 549 predecessor (549_package_addon_purchase) is pinned by checksum.
func TestCNAMEZoneRandomAllocation550Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"550_cname_zone_random_allocation.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 549", "(SELECT max(version) FROM schema_migrations) <> 549",
			"migration_id='549_package_addon_purchase'",
			"checksum_sha256='2044dcce620031ed9f6175d7d324daea65e9d3319946c70c845c0b9247cb4b90'",
			"down_checksum_sha256='90ef797a77989fcaae49bdcb092d233ee761cefd157ee7dcbf0ed33f224827c0'",
			"ERRCODE='P5500'",
			"ALTER TABLE dns_zones ADD COLUMN random_allocation boolean NOT NULL DEFAULT false",
			"CREATE INDEX dns_zones_random_allocation_550_idx ON dns_zones (scope_id) WHERE random_allocation",
		}},
		{"550_cname_zone_random_allocation.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 550", "migration_id='550_cname_zone_random_allocation'",
			"ERRCODE='P5501'", "ERRCODE='P5502'", "DROP COLUMN random_allocation",
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
}
