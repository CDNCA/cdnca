package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 387 (site TLS profile) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration387Version         = 387
	migration387ID              = "387_site_tls_profile"
	migration387PreviousID      = "386_plugin_ui_pages"
	migration387PreviousUpSHA   = "b8adf13c8b724c1e22376a55b838c94722ab58e68a70f8d94d75304c83f34ef3"
	migration387PreviousDownSHA = "216acb746ead9b0bce071f74588ea0a21defa21a3d6d2c9122a1431066a3546f"
	migration387UpSHA           = "d045cb76567eff8bba1d935f3921722678aeed08ce42a8ff291a4451d381c386"
	migration387DownSHA         = "aa21887d5a8dc806aed7333985a5a0919171c3ccd6434ce242936435ca1c412c"
)

func TestSiteTLSProfile387Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration387ID + ".up.sql", migration387UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration387Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration387Version-1),
			"migration_id='" + migration387PreviousID + "'", migration387PreviousUpSHA, migration387PreviousDownSHA,
			"ERRCODE='P3870'", "DROP CONSTRAINT sites_tls_protocols_valid_160",
			"ADD COLUMN tls_cipher_preset", "ADD COLUMN tls_ocsp_stapling", "ADD COLUMN tls_client_auth",
			"ADD COLUMN tls_client_ca_pem", "sites_tls_cipher_preset_387", "sites_tls_client_auth_387",
			"CREATE OR REPLACE FUNCTION system_configuration_v2_default_ssl",
		}},
		{migration387ID + ".down.sql", migration387DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration387Version),
			"migration_id='" + migration387ID + "'", "ERRCODE='P3871'", "ERRCODE='P3872'",
			"DROP COLUMN tls_cipher_preset", "ADD CONSTRAINT sites_tls_protocols_valid_160",
			"'recommended','legacy_tls12','legacy_full','custom'",
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
