package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	migration224UpSHA225   = "5066e72135c6b46224a0774cd8909ef78cde45c544ea8fbb69a3c5ccc38d01e5"
	migration224DownSHA225 = "748d05a3179aa4afa1c92cb98bf91f8fdfdb33aa175000f61e5066bb23c8fd23"
	migration225UpSHA      = "6ca959a26bb17feffb477cb9435e09c5b74f3183523f1c428ba4b425264b32f6"
	migration225DownSHA    = "06c67ec2c633361a7710dec75d4dea238ddc5095c1f21943ebfbddca871e0754"
)

func TestSystemConfigurationResourceOverrides225Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"224 up":   {"224_system_configuration_resource_paths.up.sql", migration224UpSHA225},
		"224 down": {"224_system_configuration_resource_paths.down.sql", migration224DownSHA225},
		"225 up":   {"225_system_configuration_resource_overrides.up.sql", migration225UpSHA},
		"225 down": {"225_system_configuration_resource_overrides.down.sql", migration225DownSHA},
	}
	contents := make(map[string][]byte, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read %s: %v", label, err)
		}
		contents[label] = payload
		if got := systemConfigurationResourceOverrides225SHA(payload); got != file.sha {
			t.Fatalf("migration %s checksum = %s, want %s", label, got, file.sha)
		}
	}

	up := string(contents["225 up"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 224",
		"version = 224 AND migration_id = '224_system_configuration_resource_paths'",
		"checksum_sha256 = '" + migration224UpSHA225 + "'",
		"down_checksum_sha256 = '" + migration224DownSHA225 + "'",
		"CREATE FUNCTION system_configuration_v2_resource_override_key_225(candidate jsonb)",
		"num_nonnulls(",
		"scope_setting := item->>'scope_id' || chr(31) || setting_key",
		"jsonb_array_length(candidate) > 256",
		"USING ERRCODE = 'P2251'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}

	down := string(contents["225 down"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 225",
		"version = 225 AND migration_id = '225_system_configuration_resource_overrides'",
		"checksum_sha256 = '" + migration225UpSHA + "'",
		"system_configuration_v2_resources_is_valid_219_compat_225(document.resources)",
		"jsonb_array_length(candidate) > 128",
		"USING ERRCODE = 'P2252'",
		"DROP FUNCTION system_configuration_v2_resources_is_valid_219_compat_225(jsonb)",
		"DROP FUNCTION system_configuration_v2_resource_override_key_225(jsonb)",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down migration missing %q", required)
		}
	}

	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{
		" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS",
		"UPDATE SYSTEM_CONFIGURATION_REVISIONS", "DELETE FROM SYSTEM_CONFIGURATION_REVISIONS",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}

func systemConfigurationResourceOverrides225SHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
