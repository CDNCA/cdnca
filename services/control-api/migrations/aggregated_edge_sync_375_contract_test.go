package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 375 (fallback origin, DCV TXT records, basic
// WAF rule kind, usage and the incremental projection queue) is a placeholder
// number (BATCH-PLUGIN 第 16 条): the merge may renumber it. Everything that
// changes with the renumbering is here.
const (
	migration375Version         = 375
	migration375ID              = "375_aggregated_edge_sync"
	migration375PreviousID      = "374_site_crs_overrides"
	migration375PreviousUpSHA   = "80d17aff7fb59880ff3c248240f661c68725cf647801616e714f3d3353812acd"
	migration375PreviousDownSHA = "62a77bf305f3436aba44ad97c75863d97a446b82f622ac1bf4d7fa0d5db7e842"
	migration375UpSHA           = "d2308d69879b56ad3e8c9f7e949040be172ee0a885c7e35ae82e7a53f36eaabf"
	migration375DownSHA         = "aa57e0f7c659acf870036af06900e12be5325abaf735b22c390aa36bdbb90071"
)

func TestAggregatedEdgeSync375Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration375ID + ".up.sql", migration375UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration375Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration375Version-1),
			"migration_id='" + migration375PreviousID + "'", migration375PreviousUpSHA, migration375PreviousDownSHA,
			"ERRCODE='P3750'", "ADD COLUMN fallback_origin text", "'waf_rule'",
			"CREATE TABLE site_supply_cdn_validation_records", "CREATE TABLE cdn_provider_usage",
			"ADD COLUMN source_generation bigint", "site_supply_cdn_sites_dirty_375_idx",
			"aggregated_edge_site_changed_375", "aggregated_edge_supply_changed_375", "SECURITY DEFINER",
		}},
		{migration375ID + ".down.sql", migration375DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration375Version),
			"migration_id='" + migration375ID + "'", "ERRCODE='P3751'", "ERRCODE='P3752'",
			"DROP TABLE site_supply_cdn_validation_records", "DROP COLUMN fallback_origin",
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
