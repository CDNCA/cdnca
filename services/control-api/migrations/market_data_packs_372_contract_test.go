package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 372 (PA-18 market data packs) is a placeholder number: the
// merge renumbers it after the head it lands on. Everything that changes with
// the renumbering is in this block.
const (
	migration372Version         = 372
	migration372ID              = "372_market_data_packs"
	migration372PreviousID      = "371_certificate_expiry_events"
	migration372PreviousUpSHA   = "60dbd16e73b00fd63bead192aecc901118eaf5ab1d507e607da512bae46e0db5"
	migration372PreviousDownSHA = "059e2a6a2c3c5498edd5ddb314728ccd3f99a336b731a64d3ec1dd26e353a98e"
	migration372UpSHA           = "fb96f7ce4d0ee1f212339007e8ce20359a395959d130c0b02a2cd7cc00170049"
	migration372DownSHA         = "79e46e119c37ce5133e30cd99b3ad7a60d96711f7b97dd10ffcd131112edc941"
)

func TestMarketDataPacks372Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration372ID + ".up.sql", migration372UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration372Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration372Version-1),
			"migration_id='" + migration372PreviousID + "'", migration372PreviousUpSHA, migration372PreviousDownSHA,
			"ERRCODE='P3720'", "ERRCODE='P3723'", "'catalog', 'import', 'tenant', 'subscription', 'market'", "source <> 'market' OR pack_id LIKE 'dev/%'",
			"market\\.[a-z][a-z0-9]*([.-][a-z0-9]+)+", "CREATE TABLE market_data_pack_sources",
			"TO cdnca_control_runtime",
		}},
		{migration372ID + ".down.sql", migration372DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration372Version),
			"migration_id='" + migration372ID + "'", "ERRCODE='P3721'", "ERRCODE='P3722'",
			"DROP TABLE market_data_pack_sources", "ADD CONSTRAINT rule_pack_artifacts_source_359",
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
