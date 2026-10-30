package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestCNAMETargetScopeDefault297Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"297_cname_target_scope_default.up.sql", "8c947a2ba91cb8a6245788916c8ced7145e4410ec4321b6df3241df074f05a1d", []string{
			"(SELECT count(*) FROM schema_migrations) <> 296", "296_market_buyer",
			"6a8d7b946285732f64191ffb4c11f8eda5b31f3b40dae0937f8361a347910b65", "ERRCODE='P2970'",
			"NEW.node_group_scope_id := NEW.tenant_scope_id",
			"CREATE TRIGGER a_cname_allocation_targets_scope_297\nBEFORE INSERT ON cname_allocation_targets",
		}},
		{"297_cname_target_scope_default.down.sql", "c20f6453b2ec1e6805f4fc6c92110ac9357bce614e5cf845ef012bfaee0cdc83", []string{
			"(SELECT count(*) FROM schema_migrations) <> 297", "297_cname_target_scope_default",
			"ERRCODE='P2971'", "DROP TRIGGER a_cname_allocation_targets_scope_297",
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
