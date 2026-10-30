package migrations

import (
	"strings"
	"testing"
)

func TestCertificateCacheDisplayIDs213Contract(t *testing.T) {
	upBytes, err := FS.ReadFile("213_certificate_cache_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := FS.ReadFile("213_certificate_cache_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"version=212 AND migration_id='212_order_display_ids'",
		"checksum_sha256='aae821853f38ee391750d5da69e346c3e29f3ffdb7e33c012421b3e753492dcd'",
		"down_checksum_sha256='7b70b5c0eea67790c9e9f238a764a50eed20006aaa18c9200f7f5b3206143764'",
		"certificate_asset_display_id_sequences", "cache_operation_display_id_sequences",
		"ALTER TABLE certificate_assets ADD COLUMN display_id bigint",
		"ALTER TABLE cache_operations ADD COLUMN display_id bigint",
		"PARTITION BY tenant_scope_id ORDER BY created_at,id",
		"PARTITION BY scope_id ORDER BY created_at,id",
		"certificate_assets_scope_display_id_unique UNIQUE(tenant_scope_id,display_id)",
		"cache_operations_scope_display_id_unique UNIQUE(scope_id,display_id)",
		"allocate_certificate_asset_display_id_213", "allocate_cache_operation_display_id_213",
		"protect_display_id_213", "NEW.display_id IS DISTINCT FROM OLD.display_id",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"version=213 AND migration_id='213_certificate_cache_display_ids'",
		"DROP COLUMN display_id", "DROP TABLE certificate_asset_display_id_sequences",
		"DROP TABLE cache_operation_display_id_sequences",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down migration missing %q", required)
		}
	}
	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{
		" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS",
		"__UP_SHA256__", "__DOWN_SHA256__",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}
