package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 402 (third-party payment provider plugins,
// high-risk confirmation gate, payment channel provider plugin) is a
// placeholder number (BATCH-PLUGIN 第 16 条): the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration402Version         = 402
	migration402ID              = "402_plugin_payment_providers"
	migration402PreviousVersion = 401
	migration402PreviousID      = "401_node_market_probe_role"
	migration402PreviousUpSHA   = "942285d0f81c261d36056e8cc84c4545554bbd062c229f9038ab68d14a26efce"
	migration402PreviousDownSHA = "dbb2e5d211afb1e0156bfa3d6ed8f52e0c829e8239c66979f743addfd85140cb"
	migration402UpSHA           = "c0f5589b6ee9ecb90569081d861f8450546078555079ad75dd91a4d5bb175689"
	migration402DownSHA         = "bef0eae462a2fbc0a8f3141fe1da268a9072d8f019a5d7a9d67825276e78df12"
)

func TestPluginPaymentProviders402Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration402ID + ".up.sql", migration402UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration402PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration402PreviousVersion),
			"migration_id='" + migration402PreviousID + "'", migration402PreviousUpSHA, migration402PreviousDownSHA,
			"ERRCODE='P4020'", "plugin_providers_payment_gate_402", "ERRCODE = 'P4021'",
			"ARRAY['dns', 'icp', 'payment', 'sms']", "'crypto', 'plugin'", "payment_channels_plugin_config_402",
		}},
		{migration402ID + ".down.sql", migration402DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration402Version),
			"migration_id='" + migration402ID + "'", "ERRCODE='P4022'", "ERRCODE='P4023'",
			"DROP FUNCTION plugin_providers_payment_gate_402()",
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
