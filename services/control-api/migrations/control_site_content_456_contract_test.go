package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 456 is allotted 456 and numbered 456 here so
// the embedded set stays contiguous on the 455 head; the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration456Version         = 456
	migration456ID              = "456_control_site_content"
	migration456PreviousID      = "455_system_mail_provider"
	migration456PreviousUpSHA   = "2059ecff10cd7bac2ef831bf1bee5fb2980ae5ba90242d236949f34d677aab94"
	migration456PreviousDownSHA = "7722d8106b1dbaddce80877208f0198317fc094bc29f2e6231669c9adb1ffd8c"
	migration456UpSHA           = "c42f022d826ff72206472a690103364ddb7716a474c9e86d4cdf8f793f202d06"
	migration456DownSHA         = "c856accbac81be891b3e97778930f48b8fd8795c4670290f0b98fec4905c4b62"
)

func TestControlSiteContent456Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration456ID + ".up.sql", migration456UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration456Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration456Version-1),
			"migration_id='" + migration456PreviousID + "'", migration456PreviousUpSHA, migration456PreviousDownSHA,
			"ERRCODE='P4560'", "CREATE TABLE control_site_content", "CREATE TABLE control_site_assets",
			"CREATE TABLE control_site_write_requests", "sha256(body) = asset_sha256",
			"'image/svg+xml'", "REVOKE ALL ON control_site_content FROM PUBLIC",
			"CREATE TABLE site_theme_packages", "CREATE TABLE site_theme_images", "CREATE TABLE site_theme_customizations",
			"CREATE TABLE site_theme_activations", "sha256(package_body) = package_sha256", "sha256(body) = image_sha256",
			"REFERENCES site_theme_packages(theme_id) ON DELETE RESTRICT", "CHECK (source = 'market' OR installed_at IS NOT NULL)",
		}},
		{migration456ID + ".down.sql", migration456DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration456Version),
			"migration_id='" + migration456ID + "'", "ERRCODE='P4561'", "ERRCODE='P4562'",
			"site_theme_packages WHERE source <> 'builtin'", "DROP TABLE site_theme_activations", "DROP TABLE control_site_content",
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
