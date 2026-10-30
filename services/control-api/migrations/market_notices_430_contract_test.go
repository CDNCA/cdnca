package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 430 (ML-10: node market notices in the notification center)
// was renumbered 428→430 by merge-batch7 (previous head 429_waf_adapt_permissions).
// Everything that changes with the renumbering is here.
const (
	migration430Version         = 430
	migration430ID              = "430_market_notices"
	migration430PreviousID      = "429_waf_adapt_permissions"
	migration430PreviousUpSHA   = "ea7538057b5aab098b210bcbc8917e6e1a06eaa042d1096a096f963467643aa1"
	migration430PreviousDownSHA = "120f1748313304637252bcb01f89bffc147635e0c152d0f3381021cb0a3ccfcb"
	migration430UpSHA           = "ebebc97d03df96f86c067c467403efad6bf973817db0a3b4df6e5cb9cdf947bd"
	migration430DownSHA         = "b434f5abca5ceb6f369528c5bf4d66177a5d4b394125161e1580ea725704e6f6"
)

// marketNoticeKinds mirrors libs/marketproto/notice.Kinds (not imported:
// migrations stay dependency free).
var marketNoticeKinds = []string{
	"market.limit.warn80", "market.limit.warn95", "market.limit.reached", "market.limit.recovered",
	"market.prepaid.low", "market.prepaid.exhausted", "market.prepaid.restored",
	"market.overdraft.warn", "market.overdraft.capped",
	"market.node.overloaded", "market.node.recovered", "market.supply.all_overloaded",
	"market.plugin.unavailable", "market.plugin.restored",
}

func TestMarketNotices430Contract(t *testing.T) {
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration430Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration430Version-1),
		"migration_id='" + migration430PreviousID + "'", migration430PreviousUpSHA, migration430PreviousDownSHA,
		"ERRCODE='P4300'",
	}
	for _, kind := range marketNoticeKinds {
		up = append(up, "('"+kind+"', true", "('"+kind+".zh-cn', 1, 'sms'", "('"+kind+".zh-cn', 1, 'email'")
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration430ID + ".up.sql", migration430UpSHA, up},
		{migration430ID + ".down.sql", migration430DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration430Version),
			"migration_id='" + migration430ID + "'", "ERRCODE='P4301'", "ERRCODE='P4302'",
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
