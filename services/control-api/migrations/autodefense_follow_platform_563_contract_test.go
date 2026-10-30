package migrations

import (
	"strings"
	"testing"
)

// Migration 563 (fix-adglobal, placeholder number): site mode follow (跟随平台)
// and the platform default_mode replacing new_site_learning. The 554
// predecessor is pinned by checksum (re-pinned when it is renumbered at merge).
func TestAutoDefenseFollowPlatform563Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"563_autodefense_follow_platform.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 562", "(SELECT max(version) FROM schema_migrations) <> 562",
			"migration_id='562_autodefense_site_allows'",
			"checksum_sha256='fe5326b9df62c6a96ad5ef2ac1e081211c97e6bc826867873a2d0924110ac985'",
			"down_checksum_sha256='91add6f612ad5bc32819f719a510df80b2c9011b5b008f5fc5e1a381e7232117'",
			"ERRCODE='P5630'", "CHECK (mode IN ('off', 'learning', 'observe', 'protect', 'follow'))",
			"(settings - 'new_site_learning') || jsonb_build_object('default_mode'",
			"UPDATE autodefense_sites SET mode='follow'", "INSERT INTO autodefense_sites(",
		}},
		{"563_autodefense_follow_platform.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 563", "migration_id='563_autodefense_follow_platform'",
			"ERRCODE='P5631'", "WHERE mode='follow'", "jsonb_build_object('new_site_learning'",
			"CHECK (mode IN ('off', 'learning', 'observe', 'protect'))",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
