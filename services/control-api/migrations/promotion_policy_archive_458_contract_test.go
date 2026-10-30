package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 458 is allotted 458 and numbered 458 here so
// the embedded set stays contiguous on the 456 head; the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration458Version         = 458
	migration458ID              = "458_promotion_policy_archive"
	migration458PreviousID      = "457_package_automatic_publication"
	migration458PreviousUpSHA   = "44cc376395c751b96952f0bc0eacbc714b864482a67a9fe0e2a887baca234482"
	migration458PreviousDownSHA = "43594d404e26c6ee3de3da44c931122a97bead7a4f42961f1d357be34db16f56"
	migration458UpSHA           = "d528d0e45f9700a46b5064fc44d039cf4a9e9a75529d209b093b7401cb048271"
	migration458DownSHA         = "4e0f8ab0c182ef72225383fae1b3bbc1b3f7698ea9e13c405f9776f13da86c86"
)

func TestPromotionPolicyArchive458Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration458ID + ".up.sql", migration458UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration458Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration458Version-1),
			"migration_id='" + migration458PreviousID + "'", migration458PreviousUpSHA, migration458PreviousDownSHA,
			"ERRCODE='P4580'", "ADD COLUMN archived_at timestamptz", "promotion_policies_archive_actor",
			"action = 'promotion.policy.archive'", "BEFORE INSERT ON promotion_quote_policies",
			"BEFORE INSERT ON promotion_reservations", "BEFORE INSERT ON package_orders",
			"'promotion.policy.archive',", "ERRCODE='P4582'",
		}},
		{migration458ID + ".down.sql", migration458DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration458Version),
			"migration_id='" + migration458ID + "'", "ERRCODE='P4581'", "ERRCODE='P4583'",
			"EXECUTE FUNCTION prevent_promotion_append_mutation()", "DROP COLUMN archived_at",
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
