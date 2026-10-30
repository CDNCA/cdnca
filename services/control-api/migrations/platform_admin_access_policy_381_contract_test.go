package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 381 (administration access allowlist) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration381Version         = 381
	migration381ID              = "381_platform_admin_access_policy"
	migration381PreviousID      = "380_identity_login_throttle"
	migration381PreviousUpSHA   = "fa85be1e51b1875460ace14fa67c04708bbdb93e1303293093e2d720a22a0bbb"
	migration381PreviousDownSHA = "b831845b02649a0fbda537fd44526bf2369611fcbfdc3e83e60a6cff7b8f19f8"
	migration381UpSHA           = "74a45f990ac91fdd3b7b250dc52b2a0fc51afb1e61666cb5ba99d30553cf7949"
	migration381DownSHA         = "812b0c1d762bb61c46284d719c14a81fc46100321fe7a864565f894d6ff73cf9"
)

func TestPlatformAdminAccessPolicy381Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration381ID + ".up.sql", migration381UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration381Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration381Version-1),
			"migration_id='" + migration381PreviousID + "'", migration381PreviousUpSHA, migration381PreviousDownSHA,
			"ERRCODE='P3810'", "CREATE TABLE platform_admin_access_policy", "CHECK (NOT enabled OR cardinality(allowlist) > 0)",
		}},
		{migration381ID + ".down.sql", migration381DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration381Version),
			"migration_id='" + migration381ID + "'", "ERRCODE='P3811'",
			"DROP TABLE platform_admin_access_policy",
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
