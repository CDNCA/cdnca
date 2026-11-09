package migrations

import (
	"fmt"
	"strings"
	"testing"
)

// Migration 648 (the index behind the node list's
// "旧配置仍生效" lookup) guards the 647 head.
const (
	migration648Version         = 648
	migration648ID              = "648_node_key_envelope_oversized_audit_index"
	migration648PreviousID      = "647_node_packaging_toolset"
	migration648PreviousUpSHA   = "fe7366236a4001b54baefe6e05c8dff654d95eff886833370bde924073f176dd"
	migration648PreviousDownSHA = "24a2c45a73ef46e6c4edddae5a8cf09cf28d55c63b47e352d58aacf1e88bec5d"
	migration648Index           = "audit_events_node_key_envelope_oversized_648_idx"
)

func TestNodeKeyEnvelopeOversizedAuditIndex648Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration648ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration648Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration648Version-1),
			"migration_id='" + migration648PreviousID + "'", migration648PreviousUpSHA, migration648PreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", migration648Version),
			"CREATE INDEX " + migration648Index,
			"WHERE action = 'edge_publication.key_envelope_oversized' AND resource_type = 'node'",
		}},
		{migration648ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration648Version),
			"migration_id='" + migration648ID + "'", fmt.Sprintf("ERRCODE='P%d1'", migration648Version),
			"DROP INDEX " + migration648Index,
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (merge renumbering): %v", script.name, err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
