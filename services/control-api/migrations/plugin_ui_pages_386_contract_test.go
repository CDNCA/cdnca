package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 386 (materialized ui_page plugin pages, the
// plugin_ui market data pack source kind) is a placeholder number
// (BATCH-PLUGIN 第 16 条): the merge may renumber it. Everything that
// changes with the renumbering is here.
const (
	migration386Version         = 386
	migration386ID              = "386_plugin_ui_pages"
	migration386PreviousID      = "385_site_traffic_limits"
	migration386PreviousUpSHA   = "6f341a154adc549a92d4ad631dcd95549ada31a5f34d522bb4b2c049ac898529"
	migration386PreviousDownSHA = "93329a6b93bf825da3a03317fa0b7a614294f0c65217abec5dad8b55e8e13137"
	migration386UpSHA           = "b8adf13c8b724c1e22376a55b838c94722ab58e68a70f8d94d75304c83f34ef3"
	migration386DownSHA         = "216acb746ead9b0bce071f74588ea0a21defa21a3d6d2c9122a1431066a3546f"
)

func TestPluginUIPages386Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration386ID + ".up.sql", migration386UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration386Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration386Version-1),
			"migration_id='" + migration386PreviousID + "'", migration386PreviousUpSHA, migration386PreviousDownSHA,
			"ERRCODE='P3860'", "CREATE TABLE plugin_ui_pages", "kind IN ('market_rule_pack', 'market_theme', 'plugin_ui')",
			"plugin_ui_pages_active_origin_386", "status IN ('active', 'withdrawn')",
		}},
		{migration386ID + ".down.sql", migration386DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration386Version),
			"migration_id='" + migration386ID + "'", "ERRCODE='P3861'", "ERRCODE='P3862'", "DROP TABLE plugin_ui_pages",
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
