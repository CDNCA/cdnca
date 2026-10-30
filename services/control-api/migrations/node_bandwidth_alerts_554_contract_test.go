package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 554 (fix-cuaccp2 NODE-N03: node bandwidth auto-disable alerts) is
// a placeholder number; the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration554Version         = 554
	migration554PreviousVersion = 553
	migration554PreviousID      = "553_aggregated_edge_observability"
	migration554PreviousUpSHA   = "6c5f692b9b40b8e332d6217ede2f7091ef4e0aaad638afcb1d4f1d2ae4e0a525"
	migration554PreviousDownSHA = "21f006ab097f84f0672acd827480b343694aa5905faa0070955512db7f0050ac"
	migration554ID              = "554_node_bandwidth_alerts"
)

func TestNodeBandwidthAlerts554Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration554ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration554PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration554PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration554PreviousVersion),
			"migration_id='" + migration554PreviousID + "'",
			"checksum_sha256='" + migration554PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration554PreviousDownSHA + "'",
			"ERRCODE='P5540'", "('node.bandwidth.exceeded', true", "('node.bandwidth.recovered', true",
			"('node.bandwidth.exceeded.zh-cn', 1, 'sms'", "('node.bandwidth.exceeded.zh-cn', 1, 'email'",
			"('node.bandwidth.recovered.zh-cn', 1, 'sms'", "('node.bandwidth.recovered.zh-cn', 1, 'email'",
			"ARRAY['node_name','node_ip','bandwidth','bandwidth_limit','occurred_at']",
		}},
		{migration554ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration554Version),
			"migration_id='" + migration554ID + "'", "ERRCODE='P5541'", "ERRCODE='P5542'",
			"DELETE FROM notification_event_policies", "DELETE FROM admin_inbox_messages",
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
	// The guard must pin the predecessor's actual checksums.
	for suffix, want := range map[string]string{".up.sql": migration554PreviousUpSHA, ".down.sql": migration554PreviousDownSHA} {
		raw, err := FS.ReadFile(migration554PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration554PreviousID, suffix, got, want)
		}
	}
}
