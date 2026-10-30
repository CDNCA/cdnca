package migrations

import (
	"strings"
	"testing"
)

func TestPlatformBrandAssets203Contract(t *testing.T) {
	up, err := FS.ReadFile("203_platform_brand_assets.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("203_platform_brand_assets.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	source := string(up)
	for _, required := range []string{
		"migration_203",
		"CREATE TABLE platform_brand_assets",
		"CREATE TABLE platform_brand_asset_write_requests",
		"asset://brand",
		"platform_brand_assets_scope_203",
		"REVOKE ALL ON platform_brand_assets, platform_brand_asset_write_requests FROM PUBLIC",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("migration 203 missing %q", required)
		}
	}
	if !strings.Contains(string(down), "DROP TABLE platform_brand_asset_write_requests") || !strings.Contains(string(down), "DROP TABLE platform_brand_assets") {
		t.Fatal("migration 203 down migration must remove both owned tables")
	}
}
