package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 433 (ML-11b: batch listing templates and idempotent batch
// items), renumbered from the 429 placeholder by merge-batch8 onto 432.
// Everything that changes with a renumbering is here.
const (
	migration433Version         = 433
	migration433ID              = "433_market_listing_batches"
	migration433PreviousID      = "432_market_supply_slot_states"
	migration433PreviousUpSHA   = "9fcb259e63ba9c0f92b06b73d85a371863f56baeef28e5b3a8fbb174d213ceab"
	migration433PreviousDownSHA = "7125b0a99e4567d5ef9ddd24e60410fa9a86cccd168b0c695d3e931276eb3ef0"
	migration433UpSHA           = "838793e1383693ab9e443b7d64cacef15dac90213b186ecdbd7de0137a20387f"
	migration433DownSHA         = "c3d43c6a5a7740499102c0b4d510203ae6cf3a37c70780d74b52502f446e1a3a"
)

func TestMarketListingBatches433Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration433ID + ".up.sql", migration433UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration433Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration433Version-1),
			"migration_id='" + migration433PreviousID + "'", migration433PreviousUpSHA, migration433PreviousDownSHA,
			"ERRCODE='P4330'", "ERRCODE='P4331'", "PRIMARY KEY (platform_scope_id, digest)",
		}},
		{migration433ID + ".down.sql", migration433DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration433Version),
			"migration_id='" + migration433ID + "'", "ERRCODE='P4332'",
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
