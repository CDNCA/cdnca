package migrations

import (
	"strings"
	"testing"
)

func TestPlatformBrandAssetsPermissions204Contract(t *testing.T) {
	up, err := FS.ReadFile("204_platform_brand_assets_permissions.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("204_platform_brand_assets_permissions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration_204",
		"203_platform_brand_assets",
		"GRANT USAGE ON SCHEMA public TO cdnca_control_app",
		"GRANT SELECT, INSERT, UPDATE, DELETE",
		"platform_brand_assets, platform_brand_asset_write_requests",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("migration 204 missing %q", required)
		}
	}
	if !strings.Contains(string(down), "REVOKE SELECT, INSERT, UPDATE, DELETE") ||
		!strings.Contains(string(down), "cdnca_control_app") {
		t.Fatal("migration 204 down must revoke application table permissions")
	}
}
