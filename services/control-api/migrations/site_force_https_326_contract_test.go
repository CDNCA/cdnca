package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (326 placeholder; guards the integration head 325). Every number the merge renumbering touches is here: the
// version, the previous head it guards on, and the script checksums.
const (
	forceHTTPSVersion         = 326
	forceHTTPSID              = "326_site_force_https"
	forceHTTPSPreviousID      = "325_edge_publication_compile_inputs_v2"
	forceHTTPSPreviousUpSHA   = "6e35017fb83ec6fdcd24838f845171589b6a621abe5084156391b776f5f0f52c"
	forceHTTPSPreviousDownSHA = "0753b89b55c8a32625d9ed994d92b889b67c39bdd05f40e24769289a29f698f2"
	forceHTTPSUpSHA           = "426b36dbec1b76641382cf268a036796e028e579276d89778f4375ced79ba576"
	forceHTTPSDownSHA         = "b5eb71acdff1b8e3f0bc9c88226a0220991bb968f17baa1a5821d792d75ef6ed"
)

func TestSiteForceHTTPS326Contract(t *testing.T) {
	previous := forceHTTPSVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{forceHTTPSID + ".up.sql", forceHTTPSUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + forceHTTPSPreviousID + "'",
			"checksum_sha256='" + forceHTTPSPreviousUpSHA + "'",
			"down_checksum_sha256='" + forceHTTPSPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", forceHTTPSVersion),
			"ADD COLUMN force_https boolean NOT NULL DEFAULT false",
			"ADD COLUMN https_redirect_port integer NOT NULL DEFAULT 0",
			"https_redirect_port::text = ANY(https_ports)",
		}},
		{forceHTTPSID + ".down.sql", forceHTTPSDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", forceHTTPSVersion),
			"migration_id='" + forceHTTPSID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", forceHTTPSVersion),
			"DROP COLUMN https_redirect_port", "DROP COLUMN force_https",
		}},
	} {
		raw, err := controlmigrations.FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		text := string(raw)
		for _, required := range script.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "ALTER TABLE"); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
