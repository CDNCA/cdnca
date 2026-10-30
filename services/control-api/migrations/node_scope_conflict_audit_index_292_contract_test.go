package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodeScopeConflictAuditIndex292Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"292_node_scope_conflict_audit_index.up.sql", "a76b9d72641858fb17f30b14b261083c6bfeb1350ab844ccc845835dc6eeab0b", []string{
			"(SELECT count(*) FROM schema_migrations) <> 291", "291_multi_tenant_node_gate",
			"c843962a9696c76cd1038ad51bbc23d13069dcfb231584098827e307142dd559", "ERRCODE='P2920'",
			"audit_events_node_scope_conflict_292_idx", "action = 'edge_publication.node_scope_conflict'",
		}},
		{"292_node_scope_conflict_audit_index.down.sql", "3d7b46b159a65c05abe4bd9bac50f750c01c09b65a1717543d9d226b32db5a54", []string{
			"(SELECT count(*) FROM schema_migrations) <> 292", "292_node_scope_conflict_audit_index",
			"ERRCODE='P2921'", "DROP INDEX audit_events_node_scope_conflict_292_idx",
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
