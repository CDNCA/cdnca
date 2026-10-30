package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestConfigVersionTelemetrySiteBindings295Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"295_config_version_telemetry_site_bindings.up.sql", "e58da204e315ca5c377f33e6db12857e74b89b313cd487d42f8a52969c1ca275", []string{
			"(SELECT count(*) FROM schema_migrations) <> 294", "294_drop_runtime_patch_policy",
			"437c67e61f9d74a93e7f4c1523c685d029cd4882fa49e8dc965b5d842afda106",
			"f87374d506b5f14723289d5b48d081bae8dfd6182504fa717f6e8c3b63482bf0", "ERRCODE='P2950'",
			"CREATE TABLE config_version_telemetry_site_bindings", "PRIMARY KEY (config_version_id, site_id)",
			"REFERENCES config_versions(id) ON DELETE RESTRICT", "ERRCODE='P2951'",
		}},
		{"295_config_version_telemetry_site_bindings.down.sql", "9cc674c7ebe732414135aec2ce5e50a746b9f6043d899d977691fa7d0ae730bc", []string{
			"(SELECT count(*) FROM schema_migrations) <> 295", "295_config_version_telemetry_site_bindings",
			"ERRCODE='P2952'", "ERRCODE='P2953'", "DROP TABLE config_version_telemetry_site_bindings",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
