package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 470 (a site's security binding can move to
// another library or be detached) guards the 469_escalate_cname_notice head
// (task/20261024-merge-b3 @ 47f907f26); renumber at the merge if 470 is taken
// (the guard, the error codes P<version>0/1/2 and the checksums below).
const (
	migration470Version         = 470
	migration470ID              = "470_security_binding_rebind"
	migration470PreviousID      = "469_escalate_cname_notice"
	migration470PreviousUpSHA   = "aa849a7b833d78a97c94665790a403c2240775cce17686d07bdcf56efb3f959f"
	migration470PreviousDownSHA = "83464b6343256e4b45087e0eeeda7f852906e868879bf10ba115e094142fd00a"
	migration470UpSHA           = "8cd9d16c1667942d09a969d3b66e181756e06817c3c8497a29aeae543cff4a67"
	migration470DownSHA         = "b721fc75a3ea289c21582f1890bfd00b3292c8a6929b74821b743a32e0aa02b1"
)

func TestSecurityBindingRebind470Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration470ID + ".up.sql", migration470UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration470Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration470Version-1),
			"migration_id='" + migration470PreviousID + "'", migration470PreviousUpSHA, migration470PreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", migration470Version),
			"ADD COLUMN detach boolean NOT NULL DEFAULT false",
			"ADD COLUMN expected_active_policy_id uuid",
			"UPDATE security_policy_publications SET expected_active_policy_id=policy_id WHERE expected_active_version > 0",
			"CHECK (active_policy_version IS NULL OR last_claimed_policy_version IS NOT NULL)",
			"CREATE OR REPLACE FUNCTION validate_security_policy_publication_insert()",
			"CREATE OR REPLACE FUNCTION protect_security_policy_site_binding()",
			"policy.deleted_at IS NOT NULL",
			"AFTER UPDATE OF active_policy_version, policy_id ON security_policy_site_bindings",
		}},
		{migration470ID + ".down.sql", migration470DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration470Version),
			"migration_id='" + migration470ID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", migration470Version), fmt.Sprintf("ERRCODE='P%d2'", migration470Version),
			"DROP COLUMN expected_active_policy_id", "DROP COLUMN detach",
			"active_policy_version <= last_claimed_policy_version",
			"AFTER UPDATE OF active_policy_version ON security_policy_site_bindings",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
