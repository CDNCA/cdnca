package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 420 (固定 strategy, origin-gated alerts,
// 保持 choices, the scheduling alert notification) is a placeholder number (BATCH-PLUGIN 第 18 条 reserves 421;
// the loader needs consecutive versions, so it sits on the integration head
// + 1). Everything that changes with the renumbering is here.
const (
	migration420Version         = 420
	migration420ID              = "420_aggregated_edge_fixed"
	migration420PreviousID      = "419_official_rule_pack_enablement"
	migration420PreviousUpSHA   = "946e4a466fd59cfe0d24eefe819f544f3bd26293e7b8ff03ad1e7cf4f864bb4c"
	migration420PreviousDownSHA = "991d8645e2aaadc71c3741c28813fb788fb4534c46804fabd1851521768558a3"
	migration420UpSHA           = "917bc1485185055f4e8442da990375423819f87e942ba80432507a24e8dd9592"
	migration420DownSHA         = "d6909aa87797a285e8843aaf0165337d06ee8798a37a16ed073265c42e874a26"
)

func TestAggregatedEdgeFixed420Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration420ID + ".up.sql", migration420UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration420Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration420Version-1),
			"migration_id='" + migration420PreviousID + "'", migration420PreviousUpSHA, migration420PreviousDownSHA,
			"ERRCODE='P4200'", "'failover', 'quality', 'fixed'",
			"'', 'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy'",
			"'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy', 'recovered'",
			"'aggregated_edge.schedule.alert'", "freeze_kept", "alert_kept",
		}},
		{migration420ID + ".down.sql", migration420DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration420Version),
			"migration_id='" + migration420ID + "'", "ERRCODE='P4201'", "ERRCODE='P4202'",
			"aggregated_edge_switch_events_reason_394_check",
			"'aggregated_edge.schedule.alert.zh-cn'",
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
