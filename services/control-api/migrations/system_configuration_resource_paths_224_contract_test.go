package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	migration219UpSHA224   = "b131d101b7190b1fd3f400085858a683a08661d643fb19c89f4bb4a3eb0137fd"
	migration219DownSHA224 = "de0e825d6152d7da2ddbe00b5f259fccb190246c9367931ed7a2167fd5033c56"
	migration223UpSHA224   = "75fdb6a530e0f3369c235aa4d45e0ebcd24be9ac2ee16b5e733ce047eaf7f719"
	migration223DownSHA224 = "fe4fa01774301dd82eb3308d06c5a06c8259c71c6acd7a414f2fc2c4646f8cda"
	migration224UpSHA      = "5066e72135c6b46224a0774cd8909ef78cde45c544ea8fbb69a3c5ccc38d01e5"
	migration224DownSHA    = "748d05a3179aa4afa1c92cb98bf91f8fdfdb33aa175000f61e5066bb23c8fd23"
)

func TestSystemConfigurationResourcePaths224Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"219 up":   {"219_system_configuration_canonical_v2.up.sql", migration219UpSHA224},
		"219 down": {"219_system_configuration_canonical_v2.down.sql", migration219DownSHA224},
		"223 up":   {"223_region_catalog.up.sql", migration223UpSHA224},
		"223 down": {"223_region_catalog.down.sql", migration223DownSHA224},
		"224 up":   {"224_system_configuration_resource_paths.up.sql", migration224UpSHA},
		"224 down": {"224_system_configuration_resource_paths.down.sql", migration224DownSHA},
	}
	contents := make(map[string][]byte, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read %s: %v", label, err)
		}
		contents[label] = payload
		if got := systemConfigurationResourcePaths224SHA(payload); got != file.sha {
			t.Fatalf("migration %s checksum = %s, want %s", label, got, file.sha)
		}
	}

	up := string(contents["224 up"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 223",
		"version = 223 AND migration_id = '223_region_catalog'",
		"checksum_sha256 = '" + migration223UpSHA224 + "'",
		"down_checksum_sha256 = '" + migration223DownSHA224 + "'",
		"CREATE FUNCTION system_configuration_v2_resource_access_log_path_224(candidate jsonb)",
		"^(?:/data/download-temp|/var/lib/cdnca)(?:/[^/]+)*/?$",
		"CREATE OR REPLACE FUNCTION system_configuration_v2_resource_site(candidate jsonb)",
		"system_configuration_json_integer(candidate->'related_config_max_times_limit', 1, 1000)",
		"system_configuration_v2_resource_access_log_path_224(candidate->'access_log_tmp_dir')",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}

	down := string(contents["224 down"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 224",
		"version = 224 AND migration_id = '224_system_configuration_resource_paths'",
		"checksum_sha256 = '" + migration224UpSHA + "'",
		"USING ERRCODE = 'P2241'",
		"system_configuration_json_integer(",
		"document.site->'related_config_max_times_limit', 1, 100",
		"document.site->>'access_log_tmp_dir' !~ '^/var/lib/cdnca(/[^/]+)*$'",
		"CREATE OR REPLACE FUNCTION system_configuration_v2_resource_site(candidate jsonb)",
		"DROP FUNCTION system_configuration_v2_resource_access_log_path_224(jsonb)",
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

func systemConfigurationResourcePaths224SHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
