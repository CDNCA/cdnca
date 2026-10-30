package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestRealtimeEmptySourceRoster278Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"278_realtime_empty_source_roster.up.sql", "bedcacd807cab19ca5fcc4f6f380e21c6d757da66dc6a2f6b3df0d5da7b90fe4", []string{
			"LOCK TABLE schema_migrations, analytics_realtime_source_rosters_247 IN ACCESS EXCLUSIVE MODE",
			"277_node_session_capabilities",
			"32fd892953ecdda2a5119ae57287ab03765c78d3b3a551f241b9ddccd295a6ff",
			"ad2055218fe73ca6506ae75273d6aec1d92c57e38f1787fe7b5adb0832d33693",
			"ERRCODE='P2780'",
			"DROP CONSTRAINT analytics_realtime_source_rosters_247_sources_check",
			"jsonb_array_length(sources) BETWEEN 0 AND 10000",
		}},
		{"278_realtime_empty_source_roster.down.sql", "3b7df217a8d2de7ce84ad14c2145a99c9bbe11bee9ecb5a4a7efdda19e6ecf49", []string{
			"(SELECT count(*) FROM schema_migrations) <> 278", "278_realtime_empty_source_roster",
			"WHERE jsonb_array_length(sources)=0", "ERRCODE='P2782'",
			"jsonb_array_length(sources) BETWEEN 1 AND 10000",
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
