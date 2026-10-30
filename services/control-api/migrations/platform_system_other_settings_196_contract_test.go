package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestPlatformSystemOtherSettings196Contract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("196_platform_system_other_settings.up.sql")
	if err != nil { t.Fatal(err) }
	down, err := controlmigrations.FS.ReadFile("196_platform_system_other_settings.down.sql")
	if err != nil { t.Fatal(err) }
	combined := string(up) + string(down)
	for _, required := range []string{
		"version=195 AND migration_id='195_platform_system_mail_settings'",
		"37f666d8f4d51db10b4ea70731ed1cf41b8005318b2d326b09cee1605906fdd0",
		"c042473c80293ae72e05bdbcec5ef64934e327280d44bfc4d7adca52f838fcf8",
		"CREATE TABLE platform_system_other_settings",
		"operation='system_other_settings.update'",
		"platform system other settings require a platform scope",
		"migration 196 rollback requires the exact verified release head",
	} {
		if !strings.Contains(combined, required) { t.Errorf("196 migration missing %q", required) }
	}
	if strings.Contains(strings.ToUpper(combined), "CASCADE") || strings.Contains(combined, "DELETE FROM schema_migrations") { t.Fatal("196 migration must not use destructive migration shortcuts") }
}
