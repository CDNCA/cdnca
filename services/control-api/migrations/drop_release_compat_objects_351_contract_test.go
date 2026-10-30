package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 351 (drop the ≤1.0.34 release compatibility
// objects) is a placeholder number: the merge renumbers it after the head it
// lands on. Everything that changes with the renumbering is in this block.
const (
	migration351Version         = 351
	migration351ID              = "351_drop_release_compat_objects"
	migration351PreviousID      = "350_aggregated_edge"
	migration351PreviousUpSHA   = "f25689a94b20c9f8f6286e2095b0831bbf11c6eb3a17326d1f6674cd3d65f9cf"
	migration351PreviousDownSHA = "0fe195c37967496d268c4d643badab6bea184c61140d650d178e40eced3495d2"
	migration351UpSHA           = "812ab13b15b806bc1f54355046f599ab3936c92b0251c0e02c0542e5b644cfb3"
	migration351DownSHA         = "5dfbdc3c31dd83c2f9df51c0fb8bed2fedc7ca5cb55caabb16cc2eb3d8f36e5e"
)

func TestDropReleaseCompatObjects351Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration351ID + ".up.sql", migration351UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration351Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration351Version-1),
			"migration_id='" + migration351PreviousID + "'", migration351PreviousUpSHA, migration351PreviousDownSHA,
			"ERRCODE='P3510'",
			"DROP TRIGGER a_cname_allocation_targets_scope_297 ON cname_allocation_targets",
			"DROP FUNCTION default_cname_target_node_group_scope_297()",
			"ALTER TABLE security_activation_capability_waits DROP COLUMN compatible_challenge",
		}},
		{migration351ID + ".down.sql", migration351DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration351Version),
			"migration_id='" + migration351ID + "'", "ERRCODE='P3511'",
			"ADD COLUMN compatible_challenge boolean NOT NULL DEFAULT false",
			"CREATE TRIGGER a_cname_allocation_targets_scope_297\nBEFORE INSERT ON cname_allocation_targets",
			"REVOKE ALL ON FUNCTION default_cname_target_node_group_scope_297() FROM PUBLIC",
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
