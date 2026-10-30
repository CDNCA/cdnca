package migrations_test

import (
	"os"
	"strings"
	"testing"
)

func TestAPIKeyPepperRotation149Contract(t *testing.T) {
	up := readAPIKeyPepper149(t, "149_api_key_pepper_rotation.up.sql")
	down := readAPIKeyPepper149(t, "149_api_key_pepper_rotation.down.sql")
	for _, required := range []string{
		"migration 149 requires the exact verified 148 release head",
		"version = 148 AND migration_id = '148_site_domains'",
		"18e34a28e5f078b55e4143a497376643bad4b8414a13bdd05d97c4be04d62ec4",
		"70a95c5d2365a40eb1c9d54a71e2ae2c9785182c5e17087bb3af70a08cc5a2c6",
		"ADD COLUMN pepper_version text",
		"api_key_pepper_version_is_valid",
		"protect_api_key_pepper_version_149",
		"secret_digest IS NULL",
		"OLD.secret_digest",
		"api_key_write_requests",
		"pepper_version",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("149 up missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 149 rollback requires the exact verified 149 head",
		"version = 149 AND migration_id = '149_api_key_pepper_rotation'",
		"32099eee305e8bd90c0b4e86392b3b7859267f9d9dd4aa5c379c8b6d1d028336",
		"migration 149 rollback would discard API key pepper version facts",
		"DROP FUNCTION protect_api_key_pepper_version_149",
		"DROP FUNCTION api_key_pepper_version_is_valid",
		"DROP COLUMN pepper_version",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("149 down missing %q", required)
		}
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("149 migration contains forbidden marker %q", forbidden)
		}
	}
}

func readAPIKeyPepper149(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
