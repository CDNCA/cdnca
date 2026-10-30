package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 587 (market.plugin.promo_charge notice; assigned 606, local head+1).
// Everything that changes with a renumbering is here.
const (
	migration587Version         = 587
	migration587ID              = "587_plugin_promo_charge_notice"
	migration587PreviousID      = "586_plugin_installation_target_binding"
	migration587PreviousUpSHA   = "36d17680071315b00035da5cb7accb75eb360e55bcd4330485a24141b87f5af6"
	migration587PreviousDownSHA = "b20a682775f47fe81728583de28f18d7e7c08b5404ccd8d9f34446572b26a395"
	migration587UpSHA           = "74a2e8867020908f3b0300d3e8c99d14b1a42c375dae5bb390d1ef2e7506a40a"
	migration587DownSHA         = "3e0af927e2169681ab11334b803d5b9231df36ec201770334c36a59677ae6b13"
)

func TestPluginPromoChargeNotice587Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration587ID + ".up.sql", migration587UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration587Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration587Version-1),
			"migration_id='" + migration587PreviousID + "'", migration587PreviousUpSHA, migration587PreviousDownSHA,
			"ERRCODE='P5870'", "('market.plugin.promo_charge', true",
			"('market.plugin.promo_charge.zh-cn', 1, 'sms'", "('market.plugin.promo_charge.zh-cn', 1, 'email'",
			"ARRAY['plugins','at','observed','currency']",
		}},
		{migration587ID + ".down.sql", migration587DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration587Version),
			"migration_id='" + migration587ID + "'", "ERRCODE='P5871'", "ERRCODE='P5872'",
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
