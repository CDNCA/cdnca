package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 488 (market.renewal.stopped / resumed
// notices) is a placeholder on 485; the merge renumbers it.
// Everything that changes with a renumbering is here.
const (
	migration488Version         = 488
	migration488ID              = "488_market_renewal_stop_notices"
	migration488PreviousID      = "487_tenant_member_password_reset_results"
	migration488PreviousUpSHA   = "b78bfc9655330cfc9cfbbc96238af8df73871768947d8b151b0db11cb14d37dd"
	migration488PreviousDownSHA = "b315adc033b593623a1eba8c4d5e94fccd2aaee43aafbea0dcf0f61ea63dd5aa"
	migration488UpSHA           = "9065189ac08869cc500223bfaf1458c6c9c994e21bf5ed1c3f8f129dfdb43692"
	migration488DownSHA         = "81a076a6a4843d9b7caaee976d631f24da10240587948cacb9d21cc50b863a7e"
)

func TestMarketRenewalStopNotices488Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration488ID + ".up.sql", migration488UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration488Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration488Version-1),
			"migration_id='" + migration488PreviousID + "'", migration488PreviousUpSHA, migration488PreviousDownSHA,
			"ERRCODE='P4880'", "('market.renewal.stopped', true", "('market.renewal.resumed', true",
			"('market.renewal.stopped.zh-cn', 1, 'sms'", "('market.renewal.stopped.zh-cn', 1, 'email'",
			"('market.renewal.resumed.zh-cn', 1, 'sms'", "('market.renewal.resumed.zh-cn', 1, 'email'",
		}},
		{migration488ID + ".down.sql", migration488DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration488Version),
			"migration_id='" + migration488ID + "'", "ERRCODE='P4881'", "ERRCODE='P4882'",
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
