package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 427 (ML-09, ADR 0012 §3.3: hidden market supply line
// groups) is a placeholder number (BATCH-PLUGIN 第 18 条 reserves 430; the
// loader needs consecutive versions, so it sits on the base head + 1).
// Everything that changes with the renumbering is here.
const (
	migration427Version         = 427
	migration427ID              = "427_market_supply_line_groups"
	migration427PreviousID      = "426_security_activation_v1_root_removed"
	migration427PreviousUpSHA   = "5b19a7a2723ac905988003efc5871be164047e09a213287275bf9f8a33b96c73"
	migration427PreviousDownSHA = "15150a88347442da8612864873d0c98ed49d1dc5f53a4e0b747b822cd069820b"
	migration427UpSHA           = "a108fd06c68a15675aace029e9a278e09c84a1569259d053ef4fcb316f9eb5aa"
	migration427DownSHA         = "0e38dc6344858f9e661065ead129785f3d36da63f5be0177188ddbe0b3c5f784"
)

func TestMarketSupplyLineGroups427Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration427ID + ".up.sql", migration427UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration427Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration427Version-1),
			"migration_id='" + migration427PreviousID + "'", migration427PreviousUpSHA, migration427PreviousDownSHA,
			"ERRCODE='P4270'", "ERRCODE='P4271'", "ERRCODE='P4272'", "purpose IN ('general', 'market_supply')",
		}},
		{migration427ID + ".down.sql", migration427DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration427Version),
			"migration_id='" + migration427ID + "'", "ERRCODE='P4273'", "ERRCODE='P4274'",
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
