package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 397 (materialized third-party provider
// plugins, installation contract state, DNS provider type plugin) is a
// placeholder number (BATCH-PLUGIN 第 16 条): the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration397Version         = 397
	migration397ID              = "397_plugin_providers"
	migration397PreviousVersion = 396
	migration397PreviousID      = "396_ge_cache"
	migration397PreviousUpSHA   = "1ad8fba779a1a603581b1074c5f48f90ca35d0e03ee2f6ec0cac864764878d90"
	migration397PreviousDownSHA = "03e4886921448fd0c46dfbcafbb0fd723c53649a67ed672c7f271cd34b4225ce"
	migration397UpSHA           = "5fa98715622e84f6d65b6ae887fca871e688140d7ea6eb950b6fed1ec5cf2513"
	migration397DownSHA         = "a2c969e2e7e2ec74394597a04b809d59eaa836c7ace95011d891434b915df978"
)

func TestPluginProviders397Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration397ID + ".up.sql", migration397UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration397PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration397PreviousVersion),
			"migration_id='" + migration397PreviousID + "'", migration397PreviousUpSHA, migration397PreviousDownSHA,
			"ERRCODE='P3970'", "CREATE TABLE plugin_providers", "plugin_providers_enable_gate_397", "ERRCODE = 'P3971'",
			"'custom_http', 'plugin'", "kind IN ('market_rule_pack', 'market_theme', 'plugin_ui', 'plugin_provider')",
		}},
		{migration397ID + ".down.sql", migration397DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration397Version),
			"migration_id='" + migration397ID + "'", "ERRCODE='P3972'", "ERRCODE='P3973'", "DROP TABLE plugin_providers",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
