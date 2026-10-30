package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 523 (the 144 WAF geo authority never reached
// a node and is dropped; branch placeholder 560, renumbered at merge): the
// up guard pins the predecessor 522's migration_id and checksums.
const (
	migration523Version         = 523
	migration523ID              = "523_waf_geo_authority_drop"
	migration523PreviousID      = "522_approval_center"
	migration523PreviousUpSHA   = "9e260151953eddb91c6142bbbc0de3e3d6e5b85df8a093731da8d62b9b723b8f"
	migration523PreviousDownSHA = "ee13721bcd5edd674f411ba6f69b2b0ec0c708718ea27c6badd77af0c83c9992"
	migration523UpSHA           = "27ae91c7c12e67da41a79ac939e1c9590034fced21fa80e01702803a834f2b9d"
	migration523DownSHA         = "e778d483115417a9f11e04004c08611826272fcbac1f9f34fc5c04f123aecaa2"
)

func TestWAFGeoAuthorityDrop523Contract(t *testing.T) {
	tables := []string{"waf_geo_binding_transitions", "waf_geo_publications", "waf_geo_catalog_revisions", "waf_geo_site_heads"}
	functions := []string{"prevent_waf_geo_truncate_144()", "validate_waf_geo_head_transition_144()",
		"protect_waf_geo_transition_144()", "protect_waf_geo_publication_144()", "protect_waf_geo_revision_144()",
		"valid_waf_geo_trusted_crawlers_144(jsonb)"}
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration523Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration523Version-1),
		"migration_id='" + migration523PreviousID + "'", migration523PreviousUpSHA, migration523PreviousDownSHA,
		"migration_id='144_waf_geo_authority'", "ERRCODE='P5230'",
	}
	down := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration523Version),
		"migration_id='" + migration523ID + "'", "ERRCODE='P5231'",
	}
	for _, table := range tables {
		up = append(up, "DROP TABLE "+table+";")
		down = append(down, "CREATE TABLE "+table+" (")
	}
	for _, function := range functions {
		up = append(up, "DROP FUNCTION "+function+";")
	}
	// The restored 144 objects are byte-for-byte 144's definitions.
	original, err := FS.ReadFile("144_waf_geo_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	definitions := string(original)[strings.Index(string(original), "CREATE FUNCTION valid_waf_geo_trusted_crawlers_144"):]
	down = append(down, definitions)
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration523ID + ".up.sql", migration523UpSHA, up},
		{migration523ID + ".down.sql", migration523DownSHA, down},
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
				t.Errorf("%s missing %.80q", script.name, required)
			}
		}
		if strings.Contains(string(raw), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
}
