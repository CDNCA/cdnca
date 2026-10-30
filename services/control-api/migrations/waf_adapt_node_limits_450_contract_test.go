package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 450 (the nodes' applied
// automatic exclusions per site). Everything that changes with a
// renumbering is here.
const (
	migration450Version         = 450
	migration450ID              = "450_waf_adapt_node_limits"
	migration450PreviousID      = "449_agent_gateway_disabled_at"
	migration450PreviousUpSHA   = "ee29f2f7729d456bd7194e9730e13ebc235b8d8e5e934895f847bebffebd8afa"
	migration450PreviousDownSHA = "dd63d5ce247fa273fae90b965776a165aca3cbde6a9e617fc26c6104a7654fda"
	migration450UpSHA           = "057dfb35fa99e6cd96d0be3dc34d1677cb9a1c7591d7e4bb2eda02aa99e6bea5"
	migration450DownSHA         = "9365c964108bf3a8a77e547911d5108c5576f777951cf41d6c72b716da31a431"
)

func TestWAFAdaptNodeLimits450Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration450ID + ".up.sql", migration450UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration450Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration450Version-1),
			"migration_id='" + migration450PreviousID + "'", migration450PreviousUpSHA, migration450PreviousDownSHA,
			"ERRCODE='P4500'", "PRIMARY KEY (tenant_scope_id, site_id, node_id)",
			"CHECK (applied + latency_trimmed + memory_trimmed = delivered)",
		}},
		{migration450ID + ".down.sql", migration450DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration450Version),
			"migration_id='" + migration450ID + "'", "ERRCODE='P4502'",
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
