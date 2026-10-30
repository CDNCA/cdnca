package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 345 (JS challenge on a wildcard site) is a
// placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is in this block.
const (
	migration345Version         = 345
	migration345ID              = "345_challenge_wildcard_site_binding"
	migration345PreviousID      = "344_waf_quick_block"
	migration345PreviousUpSHA   = "87d82def44efd10278d556dd200b3a12bf17fa04f6b0b1cb8ca95f45f366058b"
	migration345PreviousDownSHA = "938c1939ac43a039eb9239361fe6fe930a02c9ee34d0a10cb3115da8a7baf384"
	migration345UpSHA           = "4d88859e1cd695ea20c29d6466aa346aaf6f0164771d3741d7ccc6a0ec9dd69c"
	migration345DownSHA         = "af50113884d47396c6daa1dd369624b9038ca5bde76d07b5f1799e3b4eb582b2"
)

func TestChallengeWildcardSiteBinding345Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration345ID + ".up.sql", migration345UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration345Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration345Version-1),
			"migration_id='" + migration345PreviousID + "'", migration345PreviousUpSHA, migration345PreviousDownSHA,
			"ERRCODE='P3450'", "CREATE FUNCTION protect_challenge_site_binding_345()",
			"DROP TRIGGER challenge_site_bindings_protected_138 ON challenge_site_bindings_138",
			"CREATE TRIGGER challenge_site_bindings_protected_345", "ERRCODE = 'P3452'",
			"REVOKE ALL ON FUNCTION protect_challenge_site_binding_345() FROM PUBLIC",
		}},
		{migration345ID + ".down.sql", migration345DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration345Version),
			"migration_id='" + migration345ID + "'", "ERRCODE='P3451'", "ERRCODE='P3453'",
			"DROP TRIGGER challenge_site_bindings_protected_345 ON challenge_site_bindings_138",
			"EXECUTE FUNCTION protect_challenge_site_binding_138()",
			"DROP FUNCTION protect_challenge_site_binding_345()",
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
