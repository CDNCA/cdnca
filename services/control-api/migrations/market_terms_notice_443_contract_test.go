package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 443 (market.terms.changed notice) is a
// placeholder on 433; the merge renumbers it. Everything that
// changes with a renumbering is here.
const (
	migration443Version         = 443
	migration443ID              = "443_market_terms_notice"
	migration443PreviousID      = "442_market_outage_notices"
	migration443PreviousUpSHA   = "b3be37fb49931831a49ace2a8df19d6b7eda13289ab9ba23ea7cafcc2138325b"
	migration443PreviousDownSHA = "58beb8d3dd25daf2dfc8e7adbf12edc1e07d83b357af0d1f8b6da0ca682ab18f"
	migration443UpSHA           = "eb0c5f3c1c7a5126c947b8da92354bfe37a0e0bafd057881281f620dab249577"
	migration443DownSHA         = "3b39a41f9ddaadc7348e8bfb2afcc96bf5b8cb1ea9ff2863bd645e338c93a7f0"
)

func TestMarketTermsNotice443Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration443ID + ".up.sql", migration443UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration443Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration443Version-1),
			"migration_id='" + migration443PreviousID + "'", migration443PreviousUpSHA, migration443PreviousDownSHA,
			"ERRCODE='P4430'", "('market.terms.changed', true", "('market.terms.changed.zh-cn', 1, 'sms'",
			"('market.terms.changed.zh-cn', 1, 'email'",
		}},
		{migration443ID + ".down.sql", migration443DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration443Version),
			"migration_id='" + migration443ID + "'", "ERRCODE='P4431'", "ERRCODE='P4432'",
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
