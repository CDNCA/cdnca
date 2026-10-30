package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 362 (one-click read-only zone import and the
// migrate wizard) is a placeholder number: the merge renumbers it after the
// head it lands on. Everything that changes with the renumbering is here.
const (
	migration362Version         = 362
	migration362ID              = "362_aggregated_edge_import"
	migration362PreviousID      = "361_audit_unified_fields"
	migration362PreviousUpSHA   = "328119e6a5097148319fee0638682cf86e98c3ab57a8e3253a47c16ef6f9ec21"
	migration362PreviousDownSHA = "f5a6d342b089da22c413305dcd863bdc893548713c53b361b016f9f32afffc24"
	migration362UpSHA           = "25f0e327bf06645a658a6bb06ef880fa579bf619b08a376208106334002af3cd"
	migration362DownSHA         = "c4aa6d3607c8f0d7fc85ec3f4650b48e40e053c0bdf50425dccef9100419db6c"
)

func TestAggregatedEdgeImport362Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration362ID + ".up.sql", migration362UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration362Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration362Version-1),
			"migration_id='" + migration362PreviousID + "'", migration362PreviousUpSHA, migration362PreviousDownSHA,
			"ERRCODE='P3620'", "ERRCODE='P3621'", "ERRCODE='P3622'", "ERRCODE='P3623'",
			"ADD COLUMN access text NOT NULL DEFAULT 'manage'", "CREATE TABLE cdn_zone_imports",
			"CREATE TABLE cdn_import_sites", "CREATE TABLE cdn_import_migrations",
			"CREATE TRIGGER site_supply_binding_import_guard_362", "CREATE TRIGGER site_supply_cdn_config_account_362",
			"cdn_import_migrations_open_362_uidx",
		}},
		{migration362ID + ".down.sql", migration362DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration362Version),
			"migration_id='" + migration362ID + "'", "ERRCODE='P3624'", "ERRCODE='P3625'",
			"DROP TABLE cdn_zone_imports", "DROP COLUMN access",
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
