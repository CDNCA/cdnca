package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 524 (market.feedback.opened / updated notices; local 505,
// assigned 555, renumbered to 524 at merge). Everything that changes with a
// renumbering is here.
const (
	migration524Version         = 524
	migration524ID              = "524_market_feedback_notices"
	migration524PreviousID      = "523_waf_geo_authority_drop"
	migration524PreviousUpSHA   = "27ae91c7c12e67da41a79ac939e1c9590034fced21fa80e01702803a834f2b9d"
	migration524PreviousDownSHA = "e778d483115417a9f11e04004c08611826272fcbac1f9f34fc5c04f123aecaa2"
	migration524UpSHA           = "9b349165f9c0451316debe7b14810d7c303b1c09a3fe9fc0bfa8c6a33f248db9"
	migration524DownSHA         = "5349fa91a141170663cc04b9c4a1b2f6db94e81c9dcf51838aee337f1c0d8ec0"
)

func TestMarketFeedbackNotices524Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration524ID + ".up.sql", migration524UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration524Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration524Version-1),
			"migration_id='" + migration524PreviousID + "'", migration524PreviousUpSHA, migration524PreviousDownSHA,
			"ERRCODE='P5240'", "('market.feedback.opened', true", "('market.feedback.updated', true",
			"('market.feedback.opened.zh-cn', 1, 'sms'", "('market.feedback.opened.zh-cn', 1, 'email'",
			"('market.feedback.updated.zh-cn', 1, 'sms'", "('market.feedback.updated.zh-cn', 1, 'email'",
			"ARRAY['offer','subscription','feedback','category','action']",
		}},
		{migration524ID + ".down.sql", migration524DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration524Version),
			"migration_id='" + migration524ID + "'", "ERRCODE='P5241'", "ERRCODE='P5242'",
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
