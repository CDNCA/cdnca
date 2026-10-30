package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (327 placeholder). Every number the merge renumbering touches is
// here: the version, the previous head it guards on, and the script checksums.
const (
	ccSiteSettingsVersion         = 327
	ccSiteSettingsID              = "327_cc_site_settings"
	ccSiteSettingsPreviousID      = "326_site_force_https"
	ccSiteSettingsPreviousUpSHA   = "426b36dbec1b76641382cf268a036796e028e579276d89778f4375ced79ba576"
	ccSiteSettingsPreviousDownSHA = "b5eb71acdff1b8e3f0bc9c88226a0220991bb968f17baa1a5821d792d75ef6ed"
	ccSiteSettingsUpSHA           = "ea7159112cd8cd207b0d57a86de28f82c65a4b25bf13a450a340951b690c4447"
	ccSiteSettingsDownSHA         = "3aa5c37c1bd32cc711dc981f8c26cbc2f6183a50ec17a674fb385221075f6e16"
)

func TestCCSiteSettings327Contract(t *testing.T) {
	previous := ccSiteSettingsVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{ccSiteSettingsID + ".up.sql", ccSiteSettingsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + ccSiteSettingsPreviousID + "'",
			"checksum_sha256='" + ccSiteSettingsPreviousUpSHA + "'",
			"down_checksum_sha256='" + ccSiteSettingsPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", ccSiteSettingsVersion),
			"ADD COLUMN cc_settings jsonb",
			"CHECK (cc_settings IS NULL OR kind = 'cc' AND jsonb_typeof(cc_settings) = 'object')",
		}},
		{ccSiteSettingsID + ".down.sql", ccSiteSettingsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", ccSiteSettingsVersion),
			"migration_id='" + ccSiteSettingsID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", ccSiteSettingsVersion),
			"DROP COLUMN cc_settings",
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
	}
}
