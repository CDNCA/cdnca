package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 380 (sign-in throttle) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration380Version         = 380
	migration380ID              = "380_identity_login_throttle"
	migration380PreviousID      = "379_site_origin_forwarding"
	migration380PreviousUpSHA   = "8d00f648a22b4081a1a60002a7a67dd13be97ac1125e59c081c1bcd0faef2b58"
	migration380PreviousDownSHA = "2fb1f5193ad0fb705078190bd24c1d659337a4879e281b39d07b55cd9a3cac62"
	migration380UpSHA           = "fa85be1e51b1875460ace14fa67c04708bbdb93e1303293093e2d720a22a0bbb"
	migration380DownSHA         = "b831845b02649a0fbda537fd44526bf2369611fcbfdc3e83e60a6cff7b8f19f8"
)

func TestIdentityLoginThrottle380Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration380ID + ".up.sql", migration380UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration380Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration380Version-1),
			"migration_id='" + migration380PreviousID + "'", migration380PreviousUpSHA, migration380PreviousDownSHA,
			"ERRCODE='P3800'", "CREATE TABLE identity_login_attempts", "CREATE TABLE identity_login_captchas",
			"GRANT SELECT, INSERT, DELETE ON identity_login_attempts TO cdnca_control_app",
		}},
		{migration380ID + ".down.sql", migration380DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration380Version),
			"migration_id='" + migration380ID + "'", "ERRCODE='P3801'",
			"DROP TABLE identity_login_captchas", "DROP TABLE identity_login_attempts",
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
