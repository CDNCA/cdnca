package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 437 (ML-25/ML-22: market tenant plugin set and automatic
// defence caps; registered as 440), guarded on 428. Everything that changes
// with the renumbering is here.
const (
	migration437Version         = 437
	migration437PreviousVersion = 436
	migration437ID              = "437_market_supply_tenant_plugins"
	migration437PreviousID      = "436_installation_ban_state"
	migration437PreviousUpSHA   = "7e2f043d0fc778775acdd2c0d412baa46fd3fd49de1ec0fd3b849f21dc0f1c89"
	migration437PreviousDownSHA = "a161099ea6b8bb3cfe31773f0652e29ba3fc008409d2867563b58af00ff0e5b8"
	migration437UpSHA           = "b535964e274654e00a376c3a012990d39d4321e3fdfc576b1a7bd0a6ef655778"
	migration437DownSHA         = "e8513641a2746a9dc4ef39547052c318bedde26d43123ac69d60388c60316c53"
)

func TestMarketSupplyTenantPlugins437Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration437ID + ".up.sql", migration437UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration437PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration437PreviousVersion),
			"migration_id='" + migration437PreviousID + "'", migration437PreviousUpSHA, migration437PreviousDownSHA,
			"ERRCODE='P4370'", "CREATE TABLE market_supply_tenant_plugins",
		}},
		{migration437ID + ".down.sql", migration437DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration437Version),
			"migration_id='" + migration437ID + "'", "ERRCODE='P4371'", "DROP TABLE market_supply_tenant_plugins",
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
