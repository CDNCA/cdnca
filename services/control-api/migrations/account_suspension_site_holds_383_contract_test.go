package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 383 (account suspension site holds) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration383Version         = 383
	migration383ID              = "383_account_suspension_site_holds"
	migration383PreviousID      = "382_identity_session_regions"
	migration383PreviousUpSHA   = "954763dd743b2b7876e9e2793a9cdec31ca796cc468906fb6e68f45ccae9b62f"
	migration383PreviousDownSHA = "4bc1a91c144927ae77b7f07cc57c7e416a2c44696ebe1e68a11082cb0ce51282"
	migration383UpSHA           = "a2c402da2f2d338b01c61b52c985b17d2f736358275e3f05601c068402145dfd"
	migration383DownSHA         = "986483de8f74de7950de1886f3a636c2950437921abf2e5ed2c880f5341dadc2"
)

func TestAccountSuspensionSiteHolds383Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration383ID + ".up.sql", migration383UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration383Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration383Version-1),
			"migration_id='" + migration383PreviousID + "'", migration383PreviousUpSHA, migration383PreviousDownSHA,
			"ERRCODE='P3830'", "CREATE TABLE account_suspension_site_holds", "'theme_activation', 'account_suspension']::text[]",
			"'module_entitlement', 'account_suspension'));",
		}},
		{migration383ID + ".down.sql", migration383DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration383Version),
			"migration_id='" + migration383ID + "'", "ERRCODE='P3831'",
			"DROP TABLE account_suspension_site_holds", "ERRCODE='P3832'",
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
