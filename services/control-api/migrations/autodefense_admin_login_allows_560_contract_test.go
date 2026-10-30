package migrations

import (
	"strings"
	"testing"
)

// Migration 560 (fix-adplatwire, placeholder number): admin sign-in source
// IPs on the auto defense allow list. The 552 predecessor is pinned by
// checksum (re-pinned when it is renumbered at merge).
func TestAutoDefenseAdminLoginAllows560Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"560_autodefense_admin_login_allows.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 559", "(SELECT max(version) FROM schema_migrations) <> 559",
			"migration_id='559_site_dns_resolution_checks'",
			"checksum_sha256='40175e26c31666fd56387e1bee69e1982e394ba889dfb679667d7a975dec371f'",
			"down_checksum_sha256='2890be05f627c52dbb5bb9dc6c1bc1d0db62ffd41f5f19d849c6498c8cbf4271'",
			"ERRCODE='P5600'", "CREATE TABLE autodefense_admin_login_allows", "PRIMARY KEY (scope_id, cidr)",
			"REVOKE ALL ON autodefense_admin_login_allows FROM PUBLIC",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_admin_login_allows TO cdnca_control_app, cdnca_control_runtime",
		}},
		{"560_autodefense_admin_login_allows.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 560", "migration_id='560_autodefense_admin_login_allows'",
			"ERRCODE='P5601'", "DROP TABLE autodefense_admin_login_allows",
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
