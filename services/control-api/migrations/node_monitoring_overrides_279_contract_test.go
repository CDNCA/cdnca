package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodeMonitoringOverrides279Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"279_node_monitoring_overrides.up.sql", "f954c57bdafed2ee7a0381034458ce8171805949d03a74a6db3ccba45cf894ca", []string{
			"LOCK TABLE schema_migrations, nodes, node_write_requests IN ACCESS EXCLUSIVE MODE",
			"278_realtime_empty_source_roster",
			"bedcacd807cab19ca5fcc4f6f380e21c6d757da66dc6a2f6b3df0d5da7b90fe4",
			"3b7df217a8d2de7ce84ad14c2145a99c9bbe11bee9ecb5a4a7efdda19e6ecf49",
			"ERRCODE='P2790'", "CREATE TABLE node_monitoring_overrides",
			"probe_timeout_ms BETWEEN 100 AND 60000", "monitor_port BETWEEN 1 AND 65535",
			"NEW.revision <> OLD.revision + 1", "'node.monitoring_override'",
		}},
		{"279_node_monitoring_overrides.down.sql", "618c0b4546625d12d1f85da00f786f168256c174a579bd11b8666d8eb2d3bb70", []string{
			"(SELECT count(*) FROM schema_migrations) <> 279", "279_node_monitoring_overrides",
			"ERRCODE='P2793'", "DROP TABLE node_monitoring_overrides",
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
