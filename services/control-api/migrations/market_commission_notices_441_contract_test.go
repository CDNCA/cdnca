package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 441 (ML-27: direct commission prepaid notices in the
// notification center, added in merge-batch9). Everything that changes with
// a renumbering is here.
const (
	migration441Version         = 441
	migration441ID              = "441_market_commission_notices"
	migration441PreviousID      = "440_market_node_actions"
	migration441PreviousUpSHA   = "a449412615332b505ae6cb97239d00443cdfc3f809f601b7b6bb02b5e174569b"
	migration441PreviousDownSHA = "2635e5a3b6fedf85604c7136a02955f5ca2c73dc42da404e6224f056b9a06600"
	migration441UpSHA           = "2da9ce6b6eec59505b9494dd681cd62a5d9f9735881343fb0a73177121532ea5"
	migration441DownSHA         = "07d1d9b974fc28fa8a3b9d8976143d828c75051e44b1e46a2fbdc30fdc66d481"
)

// marketCommissionKinds mirrors notice.KindCommissionLow/Exhausted/Restored.
var marketCommissionKinds = []string{"market.commission.low", "market.commission.exhausted", "market.commission.restored"}

func TestMarketCommissionNotices441Contract(t *testing.T) {
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration441Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration441Version-1),
		"migration_id='" + migration441PreviousID + "'", migration441PreviousUpSHA, migration441PreviousDownSHA,
		"ERRCODE='P4410'",
	}
	for _, kind := range marketCommissionKinds {
		up = append(up, "('"+kind+"', true", "('"+kind+".zh-cn', 1, 'sms'", "('"+kind+".zh-cn', 1, 'email'")
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration441ID + ".up.sql", migration441UpSHA, up},
		{migration441ID + ".down.sql", migration441DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration441Version),
			"migration_id='" + migration441ID + "'", "ERRCODE='P4411'", "ERRCODE='P4412'",
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
