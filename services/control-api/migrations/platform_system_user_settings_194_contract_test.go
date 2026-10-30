package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestPlatformSystemUserSettings194Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("194_platform_system_user_settings.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("194_platform_system_user_settings.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(upBytes) + string(downBytes)
	for _, required := range []string{
		"version=193 AND migration_id='193_platform_system_cleanup_settings'",
		"89a1973a220e729afbcdbe9f6c5605f9a1d8ca4797f5ca7ccf751cdb30dae3d9",
		"38ce3bff16af336cff92ebed4c52c91a0e93d4059dfeb18db43efc7d8a6243b0",
		"CREATE TABLE platform_system_user_settings",
		"operation='system_user_settings.update'",
		"platform system user settings require a platform scope",
		"migration 194 rollback requires the exact verified release head",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("194 migration missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(combined), "CASCADE") || strings.Contains(combined, "DELETE FROM schema_migrations") {
		t.Fatal("194 migration must not use destructive migration shortcuts")
	}
}
