package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 528 (region catalog codes, the node region the
// control plane sends; local 528, assigned 535). Everything that changes
// with a renumbering is here.
const (
	migration528Version         = 528
	migration528ID              = "528_region_catalog_code"
	migration528PreviousID      = "527_tenant_member_invitations_drop"
	migration528PreviousUpSHA   = "810266afb33ef34a711d3da3e5606ea14819ca09491604e23ca24d1d822e2ce5"
	migration528PreviousDownSHA = "856a4c33b26b0e83167ce2185a1f3e84e3cf66ad3cd61ab2e5b046bcf263bb5d"
	migration528UpSHA           = "2b51c14bcf7f303c6303ef14b954d503a4b03fcf6511558fd6f45fd0dd097dc6"
	migration528DownSHA         = "7442ec629e3bb4afa88ac2e21375346db73003bac453d20462fa0ce41027345d"
)

func TestRegionCatalogCode528Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration528ID + ".up.sql", migration528UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration528Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration528Version-1),
			"migration_id='" + migration528PreviousID + "'", migration528PreviousUpSHA, migration528PreviousDownSHA,
			"ERRCODE='P5280'", "ERRCODE = 'P5281'", "ADD COLUMN code text",
			"region_catalog_scope_code_528_unique UNIQUE (platform_scope_id, code)",
			"'region-' || region_display_id::text", "candidate := 'default'",
			"ALTER TABLE node_ssh_install_jobs DROP COLUMN node_region",
			"ADD COLUMN regions_sha256 bytea",
		}},
		{migration528ID + ".down.sql", migration528DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration528Version),
			"migration_id='" + migration528ID + "'", "ERRCODE='P5282'", "DROP COLUMN code",
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
