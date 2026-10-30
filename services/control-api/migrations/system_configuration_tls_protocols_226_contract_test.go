package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	migration225UpSHA226   = "6ca959a26bb17feffb477cb9435e09c5b74f3183523f1c428ba4b425264b32f6"
	migration225DownSHA226 = "06c67ec2c633361a7710dec75d4dea238ddc5095c1f21943ebfbddca871e0754"
	migration226UpSHA      = "ec27c02f2461808e26f872011d6cdf6810100160039ddaeef30abddd3eaf845b"
	migration226DownSHA    = "ffde321f4610b9be49f9ce3d4a8f962fed6e8b75964c35c95008de0b3ff75327"
)

func TestSystemConfigurationTLSProtocols226Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"225 up":   {"225_system_configuration_resource_overrides.up.sql", migration225UpSHA226},
		"225 down": {"225_system_configuration_resource_overrides.down.sql", migration225DownSHA226},
		"226 up":   {"226_system_configuration_tls_protocols.up.sql", migration226UpSHA},
		"226 down": {"226_system_configuration_tls_protocols.down.sql", migration226DownSHA},
	}
	contents := make(map[string][]byte, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read %s: %v", label, err)
		}
		contents[label] = payload
		if got := systemConfigurationTLSProtocols226SHA(payload); got != file.sha {
			t.Fatalf("migration %s checksum = %s, want %s", label, got, file.sha)
		}
	}

	up := string(contents["226 up"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 225",
		"version = 225 AND migration_id = '225_system_configuration_resource_overrides'",
		"checksum_sha256 = '" + migration225UpSHA226 + "'",
		"down_checksum_sha256 = '" + migration225DownSHA226 + "'",
		"CREATE OR REPLACE FUNCTION system_configuration_v2_tls_protocols(candidate jsonb)",
		"ARRAY['SSLv2','SSLv3','TLSv1','TLSv1.1','TLSv1.2','TLSv1.3'], 1, 6",
		"USING ERRCODE = 'P2260'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}

	down := string(contents["226 down"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 226",
		"version = 226 AND migration_id = '226_system_configuration_tls_protocols'",
		"checksum_sha256 = '" + migration226UpSHA + "'",
		"{website,https,ssl,protocols}",
		"{website,origin,ssl_protocols}",
		"{values,website,ssl,protocols}",
		"{values,website,origin,ssl_protocols}",
		"ARRAY['SSLv2','SSLv3']",
		"USING ERRCODE = 'P2261'",
		"ARRAY['TLSv1','TLSv1.1','TLSv1.2','TLSv1.3'], 1, 4",
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

func systemConfigurationTLSProtocols226SHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
