package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 416 (system republication triggers
// error_page_published and origin_auth_published) is a placeholder number
// (BATCH-PLUGIN 第 16 条): the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration416Version         = 416
	migration416ID              = "416_site_facts_republication"
	migration416PreviousID      = "415_autodefense_federation"
	migration416PreviousUpSHA   = "19630777fa57cb6c4ea973bc88db4b0300c7b665c92725056aaf0276cf34927b"
	migration416PreviousDownSHA = "4d3590d7fd3ce6ab961c1a7406b71657fa370973de76f0ef0861c24459da7b7e"
	migration416UpSHA           = "c5a3dcbacd0c13c1f2ac83e987e67c31bb97138d284f2cf625a370147165cb9c"
	migration416DownSHA         = "e5a9f277dc0be1e0b9531665eb5855c80ef15b3b9154ee6a23a3f34260ceab51"
)

func TestSiteFactsRepublication416Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration416ID + ".up.sql", migration416UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration416Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration416Version-1),
			"migration_id='" + migration416PreviousID + "'", migration416PreviousUpSHA, migration416PreviousDownSHA,
			"ERRCODE='P4160'", "BETWEEN 1 AND 14", "'node_networks', 'error_page_published',\n            'origin_auth_published']::text[]",
			"'node_networks', 'error_page_published', 'origin_auth_published'));",
		}},
		{migration416ID + ".down.sql", migration416DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration416Version),
			"migration_id='" + migration416ID + "'", "ERRCODE='P4161'", "ERRCODE='P4162'", "BETWEEN 1 AND 12",
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
