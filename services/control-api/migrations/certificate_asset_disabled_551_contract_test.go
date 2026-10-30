package migrations

import (
	"strings"
	"testing"
)

// Migration 551: certificate disable/enable. The 550
// predecessor is pinned by checksum (placeholder number, renumbered on merge).
func TestCertificateAssetDisabled551Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"551_certificate_asset_disabled.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 550", "(SELECT max(version) FROM schema_migrations) <> 550",
			"migration_id='550_cname_zone_random_allocation'",
			"checksum_sha256='dc3f3042d9503ed6babb536562c921ef4cb9337e1086acf665d8282d99f57182'",
			"down_checksum_sha256='41cdc2838f64157b69ad9f9bda0967610c98a6ce8e99dee36f33dc3570b9311c'",
			"ERRCODE='P5510'", "ERRCODE='P5511'", "ERRCODE='P5512'",
			"ALTER TABLE certificate_assets ADD COLUMN disabled boolean NOT NULL DEFAULT false",
			"'certificate.asset.enable', 'certificate.asset.disable'",
			"asset.auto_renew AND NOT asset.disabled",
			"CREATE TRIGGER certificate_site_binding_facts_disabled_551 BEFORE INSERT ON certificate_site_binding_facts",
		}},
		{"551_certificate_asset_disabled.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 551", "migration_id='551_certificate_asset_disabled'",
			"ERRCODE='P5513'", "ERRCODE='P5514'", "DROP COLUMN disabled",
			"DROP FUNCTION certificate_asset_bound_551(uuid, uuid)",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
