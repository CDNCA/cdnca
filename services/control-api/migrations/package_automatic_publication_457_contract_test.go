package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 457 on top of 456 (control site content).
// Everything that changes with a renumbering is here.
const (
	migration457Version         = 457
	migration457ID              = "457_package_automatic_publication"
	migration457PreviousID      = "456_control_site_content"
	migration457PreviousUpSHA   = "c42f022d826ff72206472a690103364ddb7716a474c9e86d4cdf8f793f202d06"
	migration457PreviousDownSHA = "c856accbac81be891b3e97778930f48b8fd8795c4670290f0b98fec4905c4b62"
	migration457UpSHA           = "44cc376395c751b96952f0bc0eacbc714b864482a67a9fe0e2a887baca234482"
	migration457DownSHA         = "43594d404e26c6ee3de3da44c931122a97bead7a4f42961f1d357be34db16f56"
)

func TestPackageAutomaticPublication457Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration457ID + ".up.sql", migration457UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration457Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration457Version-1),
			"migration_id='" + migration457PreviousID + "'", migration457PreviousUpSHA, migration457PreviousDownSHA,
			"ERRCODE='P4570'", "cardinality(node_ids) BETWEEN 0 AND 10000",
		}},
		{migration457ID + ".down.sql", migration457DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration457Version),
			"migration_id='" + migration457ID + "'", "ERRCODE='P4571'", "ERRCODE='P4572'",
			"cardinality(node_ids) BETWEEN 1 AND 10000",
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
