package migrations

import (
	"strings"
	"testing"
)

// Migration 559: background DNS resolution checks behind the
// site access_readiness dns_resolved check. The 552 predecessor is pinned by
// checksum.
func TestSiteDNSResolutionChecks559Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"559_site_dns_resolution_checks.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 558", "(SELECT max(version) FROM schema_migrations) <> 558",
			"migration_id='558_market_renewal_compensated_notices'",
			"checksum_sha256='9e30e27e85c3b2663348006b58e2ce4c761b9c598f0a1f5759d3a1f2085170ab'",
			"down_checksum_sha256='ee9f945a38a7aa8b0978839b3cef82710deec109cafbb84caa275acd93f97c07'",
			"ERRCODE='P5590'", "CREATE TABLE site_dns_resolution_checks", "site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE",
			"FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE",
			"next_check_at timestamptz NOT NULL", "manual_requested_at timestamptz", "generation bigint NOT NULL DEFAULT 1",
			"CREATE INDEX site_dns_resolution_checks_due_idx ON site_dns_resolution_checks (next_check_at)",
			"REVOKE ALL ON site_dns_resolution_checks FROM PUBLIC",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON site_dns_resolution_checks TO cdnca_control_app, cdnca_control_runtime",
		}},
		{"559_site_dns_resolution_checks.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 559", "migration_id='559_site_dns_resolution_checks'",
			"ERRCODE='P5591'", "DROP TABLE site_dns_resolution_checks",
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
