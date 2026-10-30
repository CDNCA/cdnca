package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Every number the merge renumbering touches is here.
const (
	l4GuardRulesVersion         = 341
	l4GuardRulesID              = "341_l4_guard_rules"
	l4GuardRulesPreviousID      = "340_edge_signer_trust"
	l4GuardRulesPreviousUpSHA   = "2a5bbd98e64db2e52fa2e9f5683ecd8cbac139ef01e5cbaf3f41524667fea8f5"
	l4GuardRulesPreviousDownSHA = "4cd5ebdedd4e5ed677b4b1916d179a244597d4ac47605414c82aa0f88a02927f"
	l4GuardRulesUpSHA           = "986ce0399908def5abb7d0805c8c2f11767e1180a9d2957b7ee4c89db371d8cb"
	l4GuardRulesDownSHA         = "746551be8cc0506711a82f89053f715780f2667f5e921836943d31dc8e3f547c"
)

func TestL4GuardRules341Contract(t *testing.T) {
	previous := l4GuardRulesVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{l4GuardRulesID + ".up.sql", l4GuardRulesUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + l4GuardRulesPreviousID + "'",
			"checksum_sha256='" + l4GuardRulesPreviousUpSHA + "'",
			"down_checksum_sha256='" + l4GuardRulesPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", l4GuardRulesVersion),
			"ADD COLUMN guard_rules jsonb", "jsonb_array_length(rules) NOT BETWEEN 1 AND 64",
			"validate_l4_runtime_spec_334(target_stream_id,target_scope_id,target_site_id,runtime_spec-'guard_rules')",
			"l4_publish_intents_runtime_spec_341", "l4_forwards_guard_rules_341",
		}},
		{l4GuardRulesID + ".down.sql", l4GuardRulesDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", l4GuardRulesVersion),
			"migration_id='" + l4GuardRulesID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", l4GuardRulesVersion), fmt.Sprintf("ERRCODE='P%d2'", l4GuardRulesVersion),
			"l4_publish_intents_runtime_spec_334",
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
