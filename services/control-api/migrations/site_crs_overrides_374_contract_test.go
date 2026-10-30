package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 374 (PA-12, per-site CRS profile / exclusions overrides) is
// renumbered on merge (361 -> 374): the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration374Version         = 374
	migration374ID              = "374_site_crs_overrides"
	migration374PreviousID      = "373_theme_tenant_whitelabel"
	migration374PreviousUpSHA   = "bb6678b98976f84ec4c18697bd2cee84f75a604d6809359c7f5731c251c529e7"
	migration374PreviousDownSHA = "d20e3f4d63eb38883d389ee4061746c5846a66a9ee2e30854a679cb1639398a3"
	migration374UpSHA           = "80d17aff7fb59880ff3c248240f661c68725cf647801616e714f3d3353812acd"
	migration374DownSHA         = "62a77bf305f3436aba44ad97c75863d97a446b82f622ac1bf4d7fa0d5db7e842"
)

func TestSiteCRSOverrides374Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration374ID + ".up.sql", migration374UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration374Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration374Version-1),
			"migration_id='" + migration374PreviousID + "'", migration374PreviousUpSHA, migration374PreviousDownSHA,
			"ERRCODE='P3740'", "CREATE TABLE site_crs_overrides", "override <> '{}'::jsonb",
			"REFERENCES sites(scope_id, id) ON DELETE CASCADE", "CREATE TABLE site_crs_write_requests",
		}},
		{migration374ID + ".down.sql", migration374DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration374Version),
			"migration_id='" + migration374ID + "'", "ERRCODE='P3741'",
			"DROP TABLE site_crs_write_requests", "DROP TABLE site_crs_overrides",
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
