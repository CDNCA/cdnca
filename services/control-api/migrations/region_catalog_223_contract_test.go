package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	migration222UpSHA223   = "9608c52faf69e6ef329dd57e752727c6e83880b6091c88437c5277bcae16f2fc"
	migration222DownSHA223 = "dab33f6c9a728f05872b856f3e6f6788de49fd30dfc2af0ed8976b0915525b13"
	migration223UpSHA      = "75fdb6a530e0f3369c235aa4d45e0ebcd24be9ac2ee16b5e733ce047eaf7f719"
	migration223DownSHA    = "fe4fa01774301dd82eb3308d06c5a06c8259c71c6acd7a414f2fc2c4646f8cda"
)

func TestRegionCatalog223Contract(t *testing.T) {
	predecessorUp := readRegionCatalogMigration(t, "222_openresty_security_platform_scope.up.sql")
	predecessorDown := readRegionCatalogMigration(t, "222_openresty_security_platform_scope.down.sql")
	up := readRegionCatalogMigration(t, "223_region_catalog.up.sql")
	down := readRegionCatalogMigration(t, "223_region_catalog.down.sql")

	for name, check := range map[string]struct {
		payload []byte
		want    string
	}{
		"222 up": {predecessorUp, migration222UpSHA223}, "222 down": {predecessorDown, migration222DownSHA223},
		"223 up": {up, migration223UpSHA}, "223 down": {down, migration223DownSHA},
	} {
		if got := regionCatalogMigrationSHA(check.payload); got != check.want {
			t.Fatalf("migration %s checksum = %s, want %s", name, got, check.want)
		}
	}

	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 222",
		"version = 222 AND migration_id = '222_openresty_security_platform_scope'",
		"checksum_sha256 = '" + migration222UpSHA223 + "'",
		"down_checksum_sha256 = '" + migration222DownSHA223 + "'",
		"CREATE SEQUENCE region_catalog_display_id_seq AS bigint MINVALUE 1",
		"CREATE TABLE region_catalog",
		"platform_scope_id uuid NOT NULL REFERENCES access_scopes(id)",
		"display_id bigint NOT NULL DEFAULT nextval('region_catalog_display_id_seq')",
		"region_catalog_scope_name_unique UNIQUE (platform_scope_id, name)",
		"CREATE FUNCTION protect_region_catalog_display_id_223()",
		"NEW.display_id IS DISTINCT FROM OLD.display_id",
		"CREATE FUNCTION sync_node_region_catalog_223()",
		"CREATE TRIGGER nodes_region_catalog_sync_223",
		"INSERT INTO permissions(name, description) VALUES ('regions.read'",
		"role.name IN ('platform_owner', 'platform_admin')",
		"VALUES ('默认')",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 223",
		"version = 223 AND migration_id = '223_region_catalog'",
		"checksum_sha256 = '" + migration223UpSHA + "'",
		"DROP TRIGGER nodes_region_catalog_sync_223 ON nodes",
		"DROP FUNCTION sync_node_region_catalog_223()",
		"DROP TABLE region_catalog",
		"DROP SEQUENCE region_catalog_display_id_seq",
		"DELETE FROM permissions WHERE name = 'regions.read'",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}

	combined := strings.ToUpper(string(up) + string(down))
	for _, forbidden := range []string{" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS", "TENANT_ID"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}

func readRegionCatalogMigration(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func regionCatalogMigrationSHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
