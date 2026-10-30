package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 444 (ADR 0015 §3.3: payment channel scene
// market_direct, direct top-up orders/payments/report queue, notices) is a
// placeholder number (BATCH-PLUGIN 39 reserves 439); the merge renumbers it
// after the head it lands on. Everything that changes with it is here.
const (
	migration444Version         = 444
	migration444ID              = "444_market_direct_topups"
	migration444PreviousID      = "443_market_terms_notice"
	migration444PreviousUpSHA   = "eb0c5f3c1c7a5126c947b8da92354bfe37a0e0bafd057881281f620dab249577"
	migration444PreviousDownSHA = "3b39a41f9ddaadc7348e8bfb2afcc96bf5b8cb1ea9ff2863bd645e338c93a7f0"
	migration444UpSHA           = "c3584641ecff4273d47c95983ca8932dea6a6ffaef47900fddfeb2a1c7fe3df6"
	migration444DownSHA         = "ec709032b749decd863b5a7bef40d622bea6feb924b76de0fb55e0ad947a8e5a"
)

// MarketDirectTopupEventTypes are the notification events 444 adds; the
// notification packages list the same names.
var marketDirectTopupEventTypes = []string{"market.direct_topup.paid", "market.direct_topup.received",
	"payment.market_topup.rejected"}

func TestMarketDirectTopups444Contract(t *testing.T) {
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration444Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration444Version-1),
		"migration_id='" + migration444PreviousID + "'", migration444PreviousUpSHA, migration444PreviousDownSHA,
		"ERRCODE='P4440'", "ERRCODE='P4443'", "scenes <@ ARRAY['recharge', 'market_direct']::text[]",
		"CREATE TABLE market_direct_topup_orders", "CREATE TABLE market_direct_topup_payments",
		"CREATE TABLE market_direct_topup_reports", "UNIQUE (channel_id, trade_no)",
	}
	for _, event := range marketDirectTopupEventTypes {
		up = append(up, "('"+event+"', true", "('"+event+".zh-cn', 1, 'sms'", "('"+event+".zh-cn', 1, 'email'")
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration444ID + ".up.sql", migration444UpSHA, up},
		{migration444ID + ".down.sql", migration444DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration444Version),
			"migration_id='" + migration444ID + "'", "ERRCODE='P4441'", "ERRCODE='P4442'",
			"ADD CHECK (scenes = ARRAY['recharge']::text[])",
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
