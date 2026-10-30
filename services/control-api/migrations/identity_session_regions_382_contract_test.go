package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 382 (session region binding) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration382Version         = 382
	migration382ID              = "382_identity_session_regions"
	migration382PreviousID      = "381_platform_admin_access_policy"
	migration382PreviousUpSHA   = "74a45f990ac91fdd3b7b250dc52b2a0fc51afb1e61666cb5ba99d30553cf7949"
	migration382PreviousDownSHA = "812b0c1d762bb61c46284d719c14a81fc46100321fe7a864565f894d6ff73cf9"
	migration382UpSHA           = "954763dd743b2b7876e9e2793a9cdec31ca796cc468906fb6e68f45ccae9b62f"
	migration382DownSHA         = "4bc1a91c144927ae77b7f07cc57c7e416a2c44696ebe1e68a11082cb0ce51282"
)

func TestIdentitySessionRegions382Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration382ID + ".up.sql", migration382UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration382Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration382Version-1),
			"migration_id='" + migration382PreviousID + "'", migration382PreviousUpSHA, migration382PreviousDownSHA,
			"ERRCODE='P3820'", "CREATE TABLE identity_session_regions",
		}},
		{migration382ID + ".down.sql", migration382DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration382Version),
			"migration_id='" + migration382ID + "'", "ERRCODE='P3821'",
			"DROP TABLE identity_session_regions",
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
