package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 558 (market chain acceptance NM03: upstream pause
// compensation notices, upstream-pause/v1; placeholder on top of the
// integration head 557). Everything that changes with a renumbering is here.
const (
	migration558Version         = 558
	migration558ID              = "558_market_renewal_compensated_notices"
	migration558PreviousID      = "557_billing_bridge_services"
	migration558PreviousUpSHA   = "1f79a73f20d519c178b8f4f36eb7655928565333ade345bccc11d53761494826"
	migration558PreviousDownSHA = "2116e730310230bcebfe1da9167dac35beb70e01c37d4d2266f8973102a74aca"
	migration558UpSHA           = "9e30e27e85c3b2663348006b58e2ce4c761b9c598f0a1f5759d3a1f2085170ab"
	migration558DownSHA         = "ee9f945a38a7aa8b0978839b3cef82710deec109cafbb84caa275acd93f97c07"
)

func TestMarketRenewalCompensatedNotices558Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration558ID + ".up.sql", migration558UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration558Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration558Version-1),
			"migration_id='" + migration558PreviousID + "'", migration558PreviousUpSHA, migration558PreviousDownSHA,
			"ERRCODE='P5580'", "('market.renewal.compensated', true",
			"('market.renewal.compensated.zh-cn', 1, 'sms'", "('market.renewal.compensated.zh-cn', 1, 'email'",
			"ARRAY['offer','subscription','action','observed','currency','at']", "upstream-pause/v1",
			// v2 renewal stop/resume templates explain upstream_paused (marketruntime noticeTemplateVersions).
			"('market.renewal.stopped.zh-cn', 2, 'sms'", "('market.renewal.stopped.zh-cn', 2, 'email'",
			"('market.renewal.resumed.zh-cn', 2, 'sms'", "('market.renewal.resumed.zh-cn', 2, 'email'", "upstream_paused=",
		}},
		{migration558ID + ".down.sql", migration558DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration558Version),
			"migration_id='" + migration558ID + "'", "ERRCODE='P5581'", "ERRCODE='P5582'",
			"template_id = 'market.renewal.compensated.zh-cn' AND version = 1", "AND version = 2;",
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
