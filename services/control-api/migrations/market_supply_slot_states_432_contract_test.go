package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 432 (ML-18b: the leaf's cache of market slot states),
// renumbered from the 429 placeholder by merge-batch8 onto 431. Everything
// that changes with a renumbering is here.
const (
	migration432Version         = 432
	migration432ID              = "432_market_supply_slot_states"
	migration432PreviousID      = "431_market_supply_limits"
	migration432PreviousUpSHA   = "203f0861c0bfb8c347e7b680848d437bd25a541ae3721a6b5d811038949c7f69"
	migration432PreviousDownSHA = "af5fb82e49b0961644203583fdf0e00bdc4d55a60dc0cf5f7fa181003b81de3f"
	migration432UpSHA           = "9fcb259e63ba9c0f92b06b73d85a371863f56baeef28e5b3a8fbb174d213ceab"
	migration432DownSHA         = "7125b0a99e4567d5ef9ddd24e60410fa9a86cccd168b0c695d3e931276eb3ef0"
)

func TestMarketSupplySlotStates432Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration432ID + ".up.sql", migration432UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration432Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration432Version-1),
			"migration_id='" + migration432PreviousID + "'", migration432PreviousUpSHA, migration432PreviousDownSHA,
			"ERRCODE='P4320'", "state IN ('normal', 'stopped', 'cancelled')",
		}},
		{migration432ID + ".down.sql", migration432DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration432Version),
			"migration_id='" + migration432ID + "'", "ERRCODE='P4321'",
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
