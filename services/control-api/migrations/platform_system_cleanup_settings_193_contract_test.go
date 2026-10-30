package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestPlatformSystemCleanupSettings193Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("193_platform_system_cleanup_settings.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("193_platform_system_cleanup_settings.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(upBytes) + string(downBytes)
	for _, required := range []string{
		"version=192 AND migration_id='192_platform_system_settings'",
		"4eea40966f0c6b5833135d62668250f032bcd4c9d363bd2041de577c7f7a0ab0",
		"885084c8e9a5af5b0990f2a86a31761471bddf27ec5ceebf2805350d78f89047",
		"CREATE TABLE platform_system_cleanup_settings",
		"operation='system_cleanup_settings.update'",
		"platform system cleanup settings require a platform scope",
		"migration 193 rollback requires the exact verified release head",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("193 migration missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(combined), "CASCADE") || strings.Contains(combined, "DELETE FROM schema_migrations") {
		t.Fatal("193 migration must not use destructive migration shortcuts")
	}
}
