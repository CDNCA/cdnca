package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 454 is a placeholder number; the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is here.
const (
	migration454Version         = 454
	migration454ID              = "454_official_rule_pack_default_on"
	migration454PreviousID      = "453_origin_follow_redirect"
	migration454PreviousUpSHA   = "dd662c6010efd183e056c42688b6a80ca464e33846de259d4ec590e90c76fc6b"
	migration454PreviousDownSHA = "60b8427fa5730fbb9765fa97e0ff8e736e2f77e8155707b4990ba8a92d8f8318"
	migration454UpSHA           = "69639d5375f465a4ab62f6152896b12a9fbbc7f7ee6ab43bc7d01b75e1364417"
	migration454DownSHA         = "e70c492069624cabba009b0841025dedd6ca8a3ed304499d29b02c545aecc063"
)

func TestOfficialRulePackDefaultOn454Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration454ID + ".up.sql", migration454UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration454Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration454Version-1),
			"migration_id='" + migration454PreviousID + "'", migration454PreviousUpSHA, migration454PreviousDownSHA,
			"ERRCODE='P4540'", "DROP CONSTRAINT rule_pack_enablements_system_row_419",
			"state IN ('inherit', 'enabled') AND allow_lower", "ALTER COLUMN published_by_user_id DROP NOT NULL",
		}},
		{migration454ID + ".down.sql", migration454DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration454Version),
			"migration_id='" + migration454ID + "'", "ERRCODE='P4541'", "ERRCODE='P4542'",
			"ADD CONSTRAINT rule_pack_enablements_system_row_419",
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
