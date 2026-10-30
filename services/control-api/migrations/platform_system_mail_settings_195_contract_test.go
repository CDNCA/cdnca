package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestPlatformSystemMailSettings195Contract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("195_platform_system_mail_settings.up.sql")
	if err != nil { t.Fatal(err) }
	down, err := controlmigrations.FS.ReadFile("195_platform_system_mail_settings.down.sql")
	if err != nil { t.Fatal(err) }
	combined := string(up) + string(down)
	for _, required := range []string{
		"version=194 AND migration_id='194_platform_system_user_settings'",
		"9f26f465cecf170606bf5c3a65bd42aca5b0463e61ddfc1a200fe6bfd37cda3b",
		"b2e061e4a430ba356d45fec63af78aeeb71c346f9e9b791d9b9fd06b892e33fb",
		"CREATE TABLE platform_system_mail_settings",
		"operation='system_mail_settings.update'",
		"platform system mail settings require a platform scope",
		"migration 195 rollback requires the exact verified release head",
	} {
		if !strings.Contains(combined, required) { t.Errorf("195 migration missing %q", required) }
	}
	if strings.Contains(strings.ToUpper(combined), "CASCADE") || strings.Contains(combined, "DELETE FROM schema_migrations") { t.Fatal("195 migration must not use destructive migration shortcuts") }
}
