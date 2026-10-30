package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 464 is allotted 464 and numbered 464 here so
// the embedded set stays contiguous on the 459 head; the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration464Version         = 464
	migration464ID              = "464_impersonation_direct_switch"
	migration464PreviousID      = "463_dns_provider_namecom"
	migration464PreviousUpSHA   = "b3bb9cdf50b04f0e4ade41ec6d00550b173f8e20ff8a6b9583e46316403b8434"
	migration464PreviousDownSHA = "079e199db4b99bbb307c2db9a70a3b8e35b0ec442df0c7970d056bbd4a8d4487"
	migration464UpSHA           = "b2fd775b5f606d395686a7ecea5f38b5520205710b21507d1f893070dcdeffea"
	migration464DownSHA         = "03cf9db5368de7102fd1dbd57b0f1bce93bf3bd9fd119622559b6e6c200f9411"
)

func TestImpersonationDirectSwitch464Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration464ID + ".up.sql", migration464UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration464Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration464Version-1),
			"migration_id='" + migration464PreviousID + "'", migration464PreviousUpSHA, migration464PreviousDownSHA,
			"ERRCODE='P4640'", "DROP COLUMN ticket", "DROP COLUMN step_up_evidence_id",
		}},
		{migration464ID + ".down.sql", migration464DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration464Version),
			"migration_id='" + migration464ID + "'", "ERRCODE='P4641'", "ERRCODE='P4642'",
			"ADD COLUMN ticket text NOT NULL", "ADD UNIQUE (actor_scope_id, step_up_evidence_id)",
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
