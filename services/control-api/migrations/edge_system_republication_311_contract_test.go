package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 311 is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration311Version         = 311
	migration311ID              = "311_edge_system_republication"
	migration311PreviousID      = "310_notification_native_sms"
	migration311PreviousUpSHA   = "806aed64663a810fb3040f78582215f1a58baca11ddf7f5698617f4bf3cdae9c"
	migration311PreviousDownSHA = "5fe79fcecbdc45214ec6931c86778f6a5ca55f88e7f2b0db004bea6652d9e512"
	migration311UpSHA           = "c3e3272b23d5b728ac56dc1ddcb0cfbecc06c7167ca802bfc44996bc3a9ea9ef"
	migration311DownSHA         = "b2aa0eac0c6c022e024a843f8c6ed118a925f5e9ad72773afe1e8275cc3affb8"
)

func TestEdgeSystemRepublication311Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration311ID + ".up.sql", migration311UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration311Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration311Version-1),
			"migration_id='" + migration311PreviousID + "'", migration311PreviousUpSHA, migration311PreviousDownSHA,
			"ERRCODE='P3110'", "'node_capability')", "'node.capabilities_changed'", "'capability_changed'",
			"CREATE TABLE edge_system_republication_heads", "CREATE TABLE edge_system_republication_attempts",
			"CREATE TABLE edge_system_revision_segments", "CREATE TABLE edge_capability_publication_holds",
			"CREATE TABLE edge_node_capability_marks",
			"GRANT SELECT, INSERT ON edge_system_republication_attempts",
		}},
		{migration311ID + ".down.sql", migration311DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration311Version),
			"migration_id='" + migration311ID + "'", "ERRCODE='P3111'",
			"source_kind = 'node_capability'", "CHECK (source_kind IN ('site', 'l4', 'line_group', 'node_sync'))",
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
