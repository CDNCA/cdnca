package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 344 (WAF quick block) is a placeholder number: the
// merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is here.
const (
	migration344Version         = 344
	migration344ID              = "344_waf_quick_block"
	migration344PreviousID      = "343_challenge_policy_redelivery"
	migration344PreviousUpSHA   = "718012174b2f86e4e56d01da55b111ff6a44f153c9e3d35bcd765c82996602ef"
	migration344PreviousDownSHA = "d2bccbb4a57b9079a58d2fba8d77c734245268998d42d1af0e46bab37a0ede31"
	migration344UpSHA           = "87d82def44efd10278d556dd200b3a12bf17fa04f6b0b1cb8ca95f45f366058b"
	migration344DownSHA         = "938c1939ac43a039eb9239361fe6fe930a02c9ee34d0a10cb3115da8a7baf384"
)

func TestWAFQuickBlock344Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration344ID + ".up.sql", migration344UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration344Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration344Version-1),
			"migration_id='" + migration344PreviousID + "'", migration344PreviousUpSHA, migration344PreviousDownSHA,
			"ERRCODE='P3440'", "ADD COLUMN quick_block jsonb", "kind = 'waf'", "'security_policy.quick_block'",
		}},
		{migration344ID + ".down.sql", migration344DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration344Version),
			"migration_id='" + migration344ID + "'", "ERRCODE='P3441'",
			"DELETE FROM security_policy_write_requests WHERE operation='security_policy.quick_block'",
			"DROP COLUMN quick_block",
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
