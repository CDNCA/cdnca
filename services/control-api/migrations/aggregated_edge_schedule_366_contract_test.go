package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 366 (aggregated edge scheduling) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration366Version         = 366
	migration366ID              = "366_aggregated_edge_schedule"
	migration366PreviousID      = "365_theme_error_page_republication"
	migration366PreviousUpSHA   = "d31f78e809bec9b73384d05e636958c248807eec32c990f3e20f4c7d88933298"
	migration366PreviousDownSHA = "83e4153e97e6f59a52e8cb8b92aa015e00611bd3d34eec09cf8e90ffd534c3e7"
	migration366UpSHA           = "27ea5f67dd2fdf1b5d1e224021832c5401266c1223fcca08324f1f83392d1b1d"
	migration366DownSHA         = "99155af5c2dcc842ca8faa42770ccf8b2cddd212ece7b1145be983f79181da74"
)

func TestAggregatedEdgeSchedule366Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration366ID + ".up.sql", migration366UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration366Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration366Version-1),
			"migration_id='" + migration366PreviousID + "'", migration366PreviousUpSHA, migration366PreviousDownSHA,
			"ERRCODE='P3660'",
			"CREATE TABLE aggregated_edge_site_schedules", "CREATE TABLE aggregated_edge_line_targets",
			"CREATE TABLE aggregated_edge_target_health", "CREATE TABLE aggregated_edge_switch_events",
			"site_supply_bindings_line_scope_366_check",
			"ALTER TABLE site_supply_cdn_sites ADD COLUMN drained_at",
		}},
		{migration366ID + ".down.sql", migration366DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration366Version),
			"migration_id='" + migration366ID + "'", "ERRCODE='P3661'",
			"DROP TABLE aggregated_edge_line_targets", "DROP CONSTRAINT site_supply_bindings_line_scope_366_check",
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
