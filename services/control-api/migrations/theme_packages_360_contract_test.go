package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 360 (PA-17 theme packages) is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration360Version         = 360
	migration360ID              = "360_theme_packages"
	migration360PreviousID      = "359_waf_subscription_rule_packs"
	migration360PreviousUpSHA   = "d725cc551e38bbfb452048697a7fb9b23ea71c959e736548a5b082dfeb2b78e5"
	migration360PreviousDownSHA = "f72ab2b9ab9b71ac685cec05ca07618a1e559b506599325b0053f97af63c5e88"
	migration360UpSHA           = "7f508678b3f75627c6f0c7e7e9237bfc8e6d610cd70e3c834a7d1f7b649f4a3d"
	migration360DownSHA         = "601053b7cf96761a25422bb1d6a8813833c0d24c6cd3eb4cc29e958964d82289"
)

func TestThemePackages360Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration360ID + ".up.sql", migration360UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration360Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration360Version-1),
			"migration_id='" + migration360PreviousID + "'", migration360PreviousUpSHA, migration360PreviousDownSHA,
			"ERRCODE='P3600'", "CREATE TABLE theme_packages", "CREATE TABLE theme_activations",
			"CREATE TABLE theme_error_pages", "ERRCODE = 'P3601'", "ERRCODE = 'P3602'", "ERRCODE = 'P3603'",
			"platform_brand_assets_media_check_360", "'logo_dark', 'login_background', 'app_icon'",
			"REVOKE ALL ON theme_packages", "TO cdnca_control_runtime",
		}},
		{migration360ID + ".down.sql", migration360DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration360Version),
			"migration_id='" + migration360ID + "'", "ERRCODE='P3604'", "ERRCODE='P3605'",
			"ADD CONSTRAINT platform_brand_assets_check", "DROP TABLE theme_packages",
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
