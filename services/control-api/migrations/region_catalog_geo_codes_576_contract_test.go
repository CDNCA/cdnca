package migrations

import (
	"strings"
	"testing"
)

// Migration 576 (fix-mktsiteconf4, placeholder number): region catalog
// country_code (ISO 3166-1 alpha-2) and province_code (GB/T 2260, CN only).
// The 554 predecessor is pinned by checksum (re-pinned when it is renumbered
// at merge).
func TestRegionCatalogGeoCodes576Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"576_region_catalog_geo_codes.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 575", "(SELECT max(version) FROM schema_migrations) <> 575",
			"migration_id='575_node_install_trust_alerts'",
			"checksum_sha256='fb2ce0b9da4793addebaca843b2248e35358f530241325b1fa0a1445ac49aa8d'",
			"down_checksum_sha256='e57449a01afb6076e6414297ca5f03edbd7da6135695a326c1e1b8a6702f1ca0'",
			"ERRCODE='P5760'", "ADD COLUMN country_code text NOT NULL DEFAULT ''",
			"ADD COLUMN province_code text NOT NULL DEFAULT ''", "country_code ~ '^[A-Z]{2}$'",
			"country_code = 'CN' AND province_code ~ '^[1-8][0-9]0000$'",
		}},
		{"576_region_catalog_geo_codes.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 576", "migration_id='576_region_catalog_geo_codes'",
			"ERRCODE='P5761'", "DROP COLUMN province_code", "DROP COLUMN country_code",
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
