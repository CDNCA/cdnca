package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestWAFGeoAuthority144Contract(t *testing.T) {
	up := readWAFGeoAuthority144(t, "144_waf_geo_authority.up.sql")
	down := readWAFGeoAuthority144(t, "144_waf_geo_authority.down.sql")
	for _, required := range []string{
		"migration 144 requires the exact verified 143 release head",
		"version = 143 AND migration_id = '143_cache_policy_definitions'",
		"checksum_sha256 = 'bbe9d4210c9cd5d58a831e210a5a57586723824d25c1deb70cabcdf5efbd8147'",
		"down_checksum_sha256 = '872a9e22a27b3c866dec3b00df65594da978229584abbb7cd9732e6444819283'",
		"CREATE TABLE waf_geo_site_heads",
		"CREATE TABLE waf_geo_catalog_revisions",
		"CREATE TABLE waf_geo_publications",
		"CREATE TABLE waf_geo_binding_transitions",
		"REFERENCES sites(scope_id,id)",
		"trusted_crawlers jsonb",
		"user_agent_prefixes",
		"trusted_proxy_cidrs",
		"canonical_payload_sha256",
		"source_sha256",
		"protect_waf_geo_revision_144",
		"protect_waf_geo_publication_144",
		"validate_waf_geo_head_transition_144",
		"REFERENCES waf_geo_publications(tenant_scope_id,site_id,binding_revision,id)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("144 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 144 requires the exact verified 143 release head"), strings.Index(up, "CREATE TABLE waf_geo_site_heads"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("144 predecessor guard must run before the first mutation")
	}
	for _, required := range []string{
		"migration 144 rollback requires the exact verified 144 head",
		"migration 144 rollback would discard WAF geo authority facts",
		"DROP TABLE waf_geo_binding_transitions",
		"DROP TABLE waf_geo_publications",
		"DROP TABLE waf_geo_catalog_revisions",
		"DROP TABLE waf_geo_site_heads",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("144 down missing %q", required)
		}
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("144 down must not mutate the migration ledger")
	}
}

func readWAFGeoAuthority144(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
