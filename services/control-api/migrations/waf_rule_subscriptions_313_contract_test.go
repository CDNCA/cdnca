package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 313 (WAF 规则库订阅) is a placeholder number: the
// merge renumbers it after the head it lands on. Everything that changes with
// the renumbering is in this block.
const (
	migration313Version         = 313
	migration313ID              = "313_waf_rule_subscriptions"
	migration313PreviousID      = "312_node_line_endpoint_published"
	migration313PreviousUpSHA   = "9ad72f4099c7eb5a449d77b3c38a332a708f517a6f0c67a186e10954d71b109c"
	migration313PreviousDownSHA = "5a9447177396e87dd56bd2b1b9103744a11fa198a9421d66e6f116e1b0cbc11d"
	migration313UpSHA           = "8e1b9f23e46e67bcaab4ea91655cde81a18c3f0395ea1906b1d9e19f76cce4b3"
	migration313DownSHA         = "07bde19bbb5ad2a98f80df7ae103f24129cfbbff02ac539117e1e7e15f84fcb6"
)

func TestWAFRuleSubscriptions313Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration313ID + ".up.sql", migration313UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration313Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration313Version-1),
			"migration_id='" + migration313PreviousID + "'", migration313PreviousUpSHA, migration313PreviousDownSHA,
			"ERRCODE='P3130'", "CREATE TABLE waf_rule_subscriptions", "source_url ~ '^https://'",
			"interval_minutes BETWEEN 5 AND 10080", "rule_count BETWEEN 0 AND 100",
			"CHECK ((revision = 0) = (rules_sha256 IS NULL))",
		}},
		{migration313ID + ".down.sql", migration313DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration313Version),
			"migration_id='" + migration313ID + "'", "ERRCODE='P3131'",
			"IF EXISTS (SELECT 1 FROM waf_rule_subscriptions)", "DROP TABLE waf_rule_subscriptions",
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
