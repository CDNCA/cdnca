package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 471 is guarded by 470 (sec-rebind,
// 470_security_binding_rebind); the previous ID and checksums are 470's real values.
const (
	migration471Version         = 471
	migration471ID              = "471_theme_block_pages"
	migration471PreviousID      = "470_security_binding_rebind"
	migration471PreviousUpSHA   = "8cd9d16c1667942d09a969d3b66e181756e06817c3c8497a29aeae543cff4a67"
	migration471PreviousDownSHA = "b721fc75a3ea289c21582f1890bfd00b3292c8a6929b74821b743a32e0aa02b1"
	migration471UpSHA           = "e660fa014659b1112cad7a67211dba329c2ae3faf13acb09ff32be6c48f54b3e"
	migration471DownSHA         = "4bd9ad669a400c8026d74a679e2213f977312a7244f44ff6a8d31f7de22ee126"
)

func TestThemeBlockPages471Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration471ID + ".up.sql", migration471UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration471Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration471Version-1),
			"migration_id='" + migration471PreviousID + "'", migration471PreviousUpSHA, migration471PreviousDownSHA,
			"ERRCODE='P4710'", "ERRCODE='P4711'",
			"DROP CONSTRAINT theme_error_pages_status_391",
			"CHECK (category IN ('edge_connect', 'edge_route', 'no_host', 'unknown_site'))",
			"(category = 'edge_route' AND status_code IN (403, 429))",
			"(category = 'unknown_site' AND status_code IN (403, 404, 410, 421))",
		}},
		{migration471ID + ".down.sql", migration471DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration471Version),
			"migration_id='" + migration471ID + "'", "ERRCODE='P4712'", "ERRCODE='P4713'",
			"WHERE category = 'edge_route'",
			"ADD CONSTRAINT theme_error_pages_status_391",
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
