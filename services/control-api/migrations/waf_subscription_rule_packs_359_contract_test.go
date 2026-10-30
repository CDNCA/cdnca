package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 359 (PA-25, WAF rule subscriptions as user layer rule
// packs) is a placeholder number: the merge renumbers it after the head it
// lands on. Everything that changes with the renumbering is in this block.
const (
	migration359Version         = 359
	migration359ID              = "359_waf_subscription_rule_packs"
	migration359PreviousID      = "358_node_artifact_sets"
	migration359PreviousUpSHA   = "67cd69e1463ce32abf89a6dc2182185806cb260f283a31797bb8997d78831d5b"
	migration359PreviousDownSHA = "6f3c098dc885ef7709d05361c8c73046e4077274f3110aebe6920b6d523de94b"
	migration359UpSHA           = "d725cc551e38bbfb452048697a7fb9b23ea71c959e736548a5b082dfeb2b78e5"
	migration359DownSHA         = "f72ab2b9ab9b71ac685cec05ca07618a1e559b506599325b0053f97af63c5e88"
)

func TestWAFSubscriptionRulePacks359Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration359ID + ".up.sql", migration359UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration359Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration359Version-1),
			"migration_id='" + migration359PreviousID + "'", migration359PreviousUpSHA, migration359PreviousDownSHA,
			"ERRCODE='P3590'",
			"CHECK (source IN ('catalog', 'import', 'tenant', 'subscription'))",
			"CREATE TABLE waf_rule_subscription_packs",
			"CHECK (pack_id LIKE 'user/' || tenant_scope_id::text || '/waf-sub-%')",
		}},
		{migration359ID + ".down.sql", migration359DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration359Version),
			"migration_id='" + migration359ID + "'", "ERRCODE='P3591'",
			"DROP TABLE waf_rule_subscription_packs",
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
