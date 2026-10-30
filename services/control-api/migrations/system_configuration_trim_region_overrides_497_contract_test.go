package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 497: drops stored
// resources/defaults region overrides of build-time settings, keeping only the
// defaults' gzip switch and types. Branch placeholder 491 (behind nginx-region-b
// 490), renumbered to 497 behind 496_l4_origin_pool_acl at merge.
const (
	migration497Version         = 497
	migration497PreviousVersion = 496
	migration497ID              = "497_system_configuration_trim_region_overrides"
	migration497UpSHA           = "1d70f77b38fee7d68a22643bc3511ad9d8d50b008a494e707444d4b8cc659fbc"
	migration497DownSHA         = "8086cfce6e06bc5c1a414e0cf87e16bf107f929760495e5991243da74e1a680f"
)

func TestSystemConfigurationTrimRegionOverrides497Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration497ID + ".up.sql", migration497UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration497PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration497PreviousVersion),
			"migration_id='" + migration496ID + "'", migration496UpSHA, migration496DownSHA,
			"ERRCODE='P4970'", "ERRCODE='P4971'",
			"'{configuration,resources,overrides}', '[]'::jsonb",
			"SET CONSTRAINTS system_configuration_revisions_projection_consistent IMMEDIATE",
			"DISABLE TRIGGER system_configuration_revisions_protected",
			"ENABLE TRIGGER system_configuration_revisions_protected",
			"ENABLE TRIGGER system_configuration_preflights_append_only",
			"ENABLE TRIGGER system_configuration_edge_publications_append_only",
		}},
		{migration497ID + ".down.sql", migration497DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration497Version),
			"migration_id='" + migration497ID + "'", "ERRCODE='P4972'",
			"DROP FUNCTION system_configuration_trim_region_overrides_497(jsonb);",
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
