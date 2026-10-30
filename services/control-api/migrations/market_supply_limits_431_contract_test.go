package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 431 (ML-08: market_supply_limits, system trigger
// market_limits) is a placeholder number (BATCH-PLUGIN 33 reserves 431); the
// merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is here.
const (
	migration431Version         = 431
	migration431ID              = "431_market_supply_limits"
	migration431PreviousID      = "430_market_notices"
	migration431PreviousUpSHA   = "ebebc97d03df96f86c067c467403efad6bf973817db0a3b4df6e5cb9cdf947bd"
	migration431PreviousDownSHA = "b434f5abca5ceb6f369528c5bf4d66177a5d4b394125161e1580ea725704e6f6"
	migration431UpSHA           = "203f0861c0bfb8c347e7b680848d437bd25a541ae3721a6b5d811038949c7f69"
	migration431DownSHA         = "af5fb82e49b0961644203583fdf0e00bdc4d55a60dc0cf5f7fa181003b81de3f"
)

func TestMarketSupplyLimits431Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration431ID + ".up.sql", migration431UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration431Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration431Version-1),
			"migration_id='" + migration431PreviousID + "'", migration431PreviousUpSHA, migration431PreviousDownSHA,
			"ERRCODE='P4310'", "BETWEEN 1 AND 16", "'origin_failover', 'market_limits']::text[]",
			"CREATE TABLE market_supply_limits",
		}},
		{migration431ID + ".down.sql", migration431DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration431Version),
			"migration_id='" + migration431ID + "'", "ERRCODE='P4311'", "ERRCODE='P4312'", "BETWEEN 1 AND 15",
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
