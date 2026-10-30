package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestTenantNodeCarriage287Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"287_tenant_node_carriage.up.sql", "92f74575dc1f67555becf5b46e120c9e40c994f244fceee147b41ee071f00440", []string{
			"(SELECT count(*) FROM schema_migrations) <> 286", "286_cname_market_target",
			"29a9ca3e22c23af8882814dc320d6dedd702a1e30191eba0afafd7374e2a51a8", "ERRCODE='P2870'",
			"CREATE FUNCTION tenant_carries_node_287", "guard_tenant_node_carriage_287",
			"open_node_tenant_287_idx", "node_group_scope_id", "guard_cname_target_node_group_287",
		}},
		{"287_tenant_node_carriage.down.sql", "e250ee0e790beaa7c3fb1253dff4d2470a341e4d15332b4378e0ba170056f2fd", []string{
			"(SELECT count(*) FROM schema_migrations) <> 287", "287_tenant_node_carriage",
			// Facts on shared platform nodes are never dropped silently.
			"ERRCODE='P2871'", "node_group_scope_id <> tenant_scope_id",
			"security_policy_publication_targets_one_open_per_node_idx", "DROP FUNCTION tenant_carries_node_287",
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
