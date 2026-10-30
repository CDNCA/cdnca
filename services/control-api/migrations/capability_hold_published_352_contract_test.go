package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 352 (capability holds written with their
// publication) is a placeholder number: the merge renumbers it after the head
// it lands on. Everything that changes with the renumbering is in this block.
const (
	migration352Version         = 352
	migration352ID              = "352_capability_hold_published"
	migration352PreviousID      = "351_drop_release_compat_objects"
	migration352PreviousUpSHA   = "812ab13b15b806bc1f54355046f599ab3936c92b0251c0e02c0542e5b644cfb3"
	migration352PreviousDownSHA = "5dfbdc3c31dd83c2f9df51c0fb8bed2fedc7ca5cb55caabb16cc2eb3d8f36e5e"
	migration352UpSHA           = "0da091ad25a8dbca26a0dc3f5b865704d6b8357ea1da686c4c757aaea15ff64e"
	migration352DownSHA         = "fa4edbb55f03cb0c2bc93f4e30b1703d2dd0c92db817e1db5641e5a373cb600d"
)

func TestCapabilityHoldPublished352Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration352ID + ".up.sql", migration352UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration352Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration352Version-1),
			"migration_id='" + migration352PreviousID + "'", migration352PreviousUpSHA, migration352PreviousDownSHA,
			"ERRCODE='P3520'",
			"ALTER TABLE edge_capability_publication_holds ADD COLUMN published boolean NOT NULL DEFAULT false",
		}},
		{migration352ID + ".down.sql", migration352DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration352Version),
			"migration_id='" + migration352ID + "'", "ERRCODE='P3521'",
			"ALTER TABLE edge_capability_publication_holds DROP COLUMN published",
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
