package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 442 (ML-31: zero-online supply notices, ADR 0012 §24) is a
// placeholder number on top of the local head 430; everything that changes
// with the renumbering is here.
const (
	migration442Version         = 442
	migration442ID              = "442_market_outage_notices"
	migration442PreviousID      = "441_market_commission_notices"
	migration442PreviousUpSHA   = "2da9ce6b6eec59505b9494dd681cd62a5d9f9735881343fb0a73177121532ea5"
	migration442PreviousDownSHA = "07d1d9b974fc28fa8a3b9d8976143d828c75051e44b1e46a2fbdc30fdc66d481"
	migration442UpSHA           = "b3be37fb49931831a49ace2a8df19d6b7eda13289ab9ba23ea7cafcc2138325b"
	migration442DownSHA         = "58beb8d3dd25daf2dfc8e7adbf12edc1e07d83b357af0d1f8b6da0ca682ab18f"
)

// marketOutageNoticeKinds mirrors the §24 kinds of libs/marketproto/notice.
var marketOutageNoticeKinds = []string{"market.supply.outage", "market.supply.restored", "market.supply.cancel_available"}

func TestMarketOutageNotices442Contract(t *testing.T) {
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration442Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration442Version-1),
		"migration_id='" + migration442PreviousID + "'", migration442PreviousUpSHA, migration442PreviousDownSHA,
		"ERRCODE='P4420'",
	}
	for _, kind := range marketOutageNoticeKinds {
		up = append(up, "('"+kind+"', true", "('"+kind+".zh-cn', 1, 'sms'", "('"+kind+".zh-cn', 1, 'email'")
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration442ID + ".up.sql", migration442UpSHA, up},
		{migration442ID + ".down.sql", migration442DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration442Version),
			"migration_id='" + migration442ID + "'", "ERRCODE='P4421'", "ERRCODE='P4422'",
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
