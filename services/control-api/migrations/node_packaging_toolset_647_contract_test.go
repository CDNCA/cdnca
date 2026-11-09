package migrations

import (
	"fmt"
	"strings"
	"testing"
)

// Migration 647 (node_presence.toolset_*) guards the 646 head.
const (
	migration647Version         = 647
	migration647ID              = "647_node_packaging_toolset"
	migration647PreviousID      = "646_challenge_pow_difficulty"
	migration647PreviousUpSHA   = "fbceec4e1780af8f5eb4123542667e6fe020c574fca67283e17f0a1f8ebc93f3"
	migration647PreviousDownSHA = "f6b712f21df0b4f6138bfbed0122f5f5a34e78506358aadca1c70ea7c7992c34"
)

func TestNodePackagingToolset647Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration647ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration647Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration647Version-1),
			"migration_id='" + migration647PreviousID + "'", migration647PreviousUpSHA, migration647PreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", migration647Version),
			"toolset_refresh_status IN ('none', 'unknown', 'ok', 'failed', 'skipped')",
			"toolset_helper_status IN ('ok', 'unchanged', 'failed', 'skipped')",
		}},
		{migration647ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration647Version),
			"migration_id='" + migration647ID + "'", fmt.Sprintf("ERRCODE='P%d1'", migration647Version),
			"DROP COLUMN toolset_refresh_status", "DROP COLUMN toolset_refresh_version", "DROP COLUMN toolset_refresh_reason",
			"DROP COLUMN toolset_refreshed_at", "DROP COLUMN toolset_helper_status", "DROP COLUMN toolset_helper_reason",
			"DROP COLUMN toolset_scripts_sha256", "DROP COLUMN toolset_helper_sha256",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (merge renumbering): %v", script.name, err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
