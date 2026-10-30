package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 318 (stop overlay) is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration318Version         = 318
	migration318ID              = "318_edge_publication_compile_inputs"
	migration318PreviousID      = "317_identity_secondary_verification_site_holds"
	migration318PreviousUpSHA   = "64ca2e1ae3498152b5b0d9d28f494f031de87d2ecd8c8416e7163c3ddd510cac"
	migration318PreviousDownSHA = "926397567843234f34420ae3ba06c9d298044b59ff903d1cfca1adf64f9e1cbb"
	migration318UpSHA           = "9b31c6f7d9f9247e3fd02d9e9b85955f672b46b8b6cbae96c614d63f0ae58e1b"
	migration318DownSHA         = "cd2ae2c483ec22bd32f36c146b7087a3464e9e05025f71833ebc1fbc333e57c8"
)

func TestEdgePublicationCompileInputs318Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration318ID + ".up.sql", migration318UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration318Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration318Version-1),
			"migration_id='" + migration318PreviousID + "'", migration318PreviousUpSHA, migration318PreviousDownSHA,
			"ERRCODE='P3180'", "CREATE TABLE edge_publication_compile_inputs", "overlay boolean NOT NULL",
			"GRANT SELECT, INSERT ON edge_publication_compile_inputs",
		}},
		{migration318ID + ".down.sql", migration318DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration318Version),
			"migration_id='" + migration318ID + "'", "ERRCODE='P3182'", "DROP TABLE edge_publication_compile_inputs",
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
