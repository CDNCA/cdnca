package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	regionCatalogManagement235UpSHA      = "165c59e45df388ca3105f7627e617aab7b5bdd59fcc2557d63148ee5003b0f8d"
	regionCatalogManagement235DownSHA    = "0491b8691f7c8271073d758137d77acc9f8d8cac3cfa38a7b49c1028fec92e2d"
	regionCatalogManagement235ParentUp   = nodeLineGroupReferenceFields234UpSHA
	regionCatalogManagement235ParentDown = nodeLineGroupReferenceFields234DownSHA
)

func TestRegionCatalogManagement235Contract(t *testing.T) {
	files := map[string]struct{ name, sha string }{
		"up":   {"235_region_catalog_management.up.sql", regionCatalogManagement235UpSHA},
		"down": {"235_region_catalog_management.down.sql", regionCatalogManagement235DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 235 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 235 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	up := contents["up"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 234",
		"version = 234 AND migration_id = '234_node_line_group_reference_fields'",
		regionCatalogManagement235ParentUp,
		regionCatalogManagement235ParentDown,
		"INSERT INTO permissions(name, description)",
		"'regions.manage'",
		"ADD COLUMN description text NOT NULL DEFAULT ''",
		"ADD COLUMN l2_check_port integer NOT NULL DEFAULT 80",
		"ADD COLUMN sort_order integer NOT NULL DEFAULT 100",
		"ADD COLUMN revision bigint NOT NULL DEFAULT 1",
		"CREATE FUNCTION protect_region_catalog_management_235()",
		"referenced region cannot be deleted",
		"referenced region cannot be renamed",
		"CREATE TABLE region_catalog_write_requests",
		"UNIQUE(actor_user_id, operation, idempotency_key)",
		"CREATE FUNCTION protect_region_catalog_write_request_235()",
		"BEFORE TRUNCATE ON region_catalog_write_requests",
		"GRANT UPDATE, DELETE ON region_catalog TO cdnca_control_app",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 235 up is missing %q", required)
		}
	}

	down := contents["down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 235",
		"version = 235 AND migration_id = '235_region_catalog_management'",
		regionCatalogManagement235UpSHA,
		"rollback cannot discard region changes or idempotency receipts",
		"USING ERRCODE = 'P2353'",
		"DROP TABLE region_catalog_write_requests",
		"DROP FUNCTION protect_region_catalog_management_235()",
		"DROP COLUMN revision",
		"DELETE FROM permissions WHERE name = 'regions.manage'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 235 down is missing %q", required)
		}
	}

	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{" CASCADE", "DELETE FROM SCHEMA_MIGRATIONS", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration 235 contains forbidden token %q", forbidden)
		}
	}
	if guard, mutation := strings.Index(down, "migration 235 rollback requires the exact verified 235 release head"),
		strings.Index(down, "REVOKE SELECT, INSERT, UPDATE"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 235 rollback guards must run before the first rollback mutation")
	}
}
