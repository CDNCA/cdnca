package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 325 (v2 stop overlay) is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration325Version         = 325
	migration325ID              = "325_edge_publication_compile_inputs_v2"
	migration325PreviousID      = "324_system_republication_secondary_verification"
	migration325PreviousUpSHA   = "eac4de7e8d9d3300b841caacef1293550623edd4ae3834f6376912f57112412a"
	migration325PreviousDownSHA = "82429290291a45689ebe035f9f3af3fb9f2dafc949b4a077e2c2587effbf143e"
	migration325UpSHA           = "6e35017fb83ec6fdcd24838f845171589b6a621abe5084156391b776f5f0f52c"
	migration325DownSHA         = "0753b89b55c8a32625d9ed994d92b889b67c39bdd05f40e24769289a29f698f2"
)

func TestEdgePublicationCompileInputsV2325Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration325ID + ".up.sql", migration325UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration325Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration325Version-1),
			"migration_id='" + migration325PreviousID + "'", migration325PreviousUpSHA, migration325PreviousDownSHA,
			"ERRCODE='P3250'", "ADD COLUMN site_runtime_v2 jsonb", "CHECK ((spec IS NULL) <> (site_runtime_v2 IS NULL))",
		}},
		{migration325ID + ".down.sql", migration325DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration325Version),
			"migration_id='" + migration325ID + "'", "ERRCODE='P3251'", "DROP COLUMN site_runtime_v2",
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
