package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 445 (anti-abscond deposit notices, ADR 0015 §11)
// is a placeholder number on top of the local head 434; everything that
// changes with the renumbering is here.
const (
	migration445Version         = 445
	migration445ID              = "445_market_deposit_notices"
	migration445PreviousID      = "444_market_direct_topups"
	migration445PreviousUpSHA   = "c3584641ecff4273d47c95983ca8932dea6a6ffaef47900fddfeb2a1c7fe3df6"
	migration445PreviousDownSHA = "ec709032b749decd863b5a7bef40d622bea6feb924b76de0fb55e0ad947a8e5a"
	migration445UpSHA           = "4b3158dd2587cc14bcbe1b3f2b3614f46a5f9027ed716bcf34c2a50a28dc10c3"
	migration445DownSHA         = "4ec4556cca071125de252c20886aef624d78da41bc699f8983a71bc75e173579"
)

// marketDepositNoticeKinds mirrors the §11 kinds of libs/marketproto/notice.
var marketDepositNoticeKinds = []string{"market.seller.deposit_mode", "market.seller.deposit_shortfall", "market.seller.default_compensated", "market.seller.defaulted"}

func TestMarketDepositNotices445Contract(t *testing.T) {
	up := []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration445Version-1),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration445Version-1),
		"migration_id='" + migration445PreviousID + "'", migration445PreviousUpSHA, migration445PreviousDownSHA,
		"ERRCODE='P4450'",
	}
	for _, kind := range marketDepositNoticeKinds {
		up = append(up, "('"+kind+"', true", "('"+kind+".zh-cn', 1, 'sms'", "('"+kind+".zh-cn', 1, 'email'")
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration445ID + ".up.sql", migration445UpSHA, up},
		{migration445ID + ".down.sql", migration445DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration445Version),
			"migration_id='" + migration445ID + "'", "ERRCODE='P4451'", "ERRCODE='P4452'",
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
