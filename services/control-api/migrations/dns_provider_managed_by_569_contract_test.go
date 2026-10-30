package migrations

import (
	"strings"
	"testing"
)

// Migration 569: dns_providers.managed_by
// separates the platform DNS copy from a tenant's own accounts. The 552
// predecessor is pinned by checksum.
func TestDNSProviderManagedBy569Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"569_dns_provider_managed_by.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 568", "(SELECT max(version) FROM schema_migrations) <> 568",
			"migration_id='568_account_login_captcha_replay'",
			"checksum_sha256='dd0bd4387c83298b049f0853df143ca205971964254f9edad685587885f92cca'",
			"down_checksum_sha256='6a1b72a66a3297c3acb9b3f3f4a9f07f5cc96e50af3577c1b60a3a9de9dbefb0'",
			"ERRCODE='P5690'",
			"ADD COLUMN managed_by text NOT NULL DEFAULT 'tenant' CHECK (managed_by IN ('tenant', 'platform'))",
		}},
		{"569_dns_provider_managed_by.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 569", "migration_id='569_dns_provider_managed_by'",
			"ERRCODE='P5691'", "ALTER TABLE dns_providers DROP COLUMN managed_by",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
