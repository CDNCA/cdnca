package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 440 (ML-23/ML-24: market_node_action_queue and the
// notices market.node.action, market.site.paused, market.site.resumed) is a local number on top of 431; the merge
// renumbers it. Everything that changes with the renumbering is here.
const (
	migration440Version         = 440
	migration440ID              = "440_market_node_actions"
	migration440PreviousID      = "439_market_complaint_notices"
	migration440PreviousUpSHA   = "1165c0df8220c4b5e9c385bb2734f176ed8dbc7da4edfe8a8508482ded48e039"
	migration440PreviousDownSHA = "1a20978565668bb12c43091033ef38faf40f7ba5db8149ae0e7a1eb1bce0dae3"
	migration440UpSHA           = "a449412615332b505ae6cb97239d00443cdfc3f809f601b7b6bb02b5e174569b"
	migration440DownSHA         = "2635e5a3b6fedf85604c7136a02955f5ca2c73dc42da404e6224f056b9a06600"
)

// marketNodeActionKinds mirrors the libs/marketproto/notice kinds ML-23/24 add.
var marketNodeActionKinds = []string{"market.node.action", "market.site.paused", "market.site.resumed"}

func TestMarketNodeActions440Contract(t *testing.T) {
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration440Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration440Version-1),
		"migration_id='" + migration440PreviousID + "'", migration440PreviousUpSHA, migration440PreviousDownSHA,
		"ERRCODE='P4400'", "CREATE TABLE market_node_action_queue",
		"CHECK (site_id IS NULL OR (source = 'autodefense' AND level >= 4))",
	}
	for _, kind := range marketNodeActionKinds {
		up = append(up, "('"+kind+"', true", "('"+kind+".zh-cn', 1, 'sms'", "('"+kind+".zh-cn', 1, 'email'")
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration440ID + ".up.sql", migration440UpSHA, up},
		{migration440ID + ".down.sql", migration440DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration440Version),
			"migration_id='" + migration440ID + "'", "ERRCODE='P4401'", "ERRCODE='P4402'", "ERRCODE='P4403'",
			"DROP TABLE market_node_action_queue",
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
