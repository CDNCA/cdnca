package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 512: the site's WAF grey zone repeat
// threshold / window. Branch placeholder 520 behind empty placeholders
// 500-519; the merge dropped the placeholders and gave it 512 behind 511.
// Everything that changes with the number is here.
const (
	migration512Version  = 512
	migration512Previous = 511
	migration512ID       = "512_waf_adapt_repeat_site"
	migration512UpSHA    = "15653b01b18cbd95b9f5c205da9d4cb6376e2051fe64e27c16f5cbe1619e1ccd"
	migration512DownSHA  = "09536ef812f97e50db7aba8227efe1e2d331e8e4a198ac2680312cdad92b22ec"
)

func TestWAFAdaptRepeatSite512Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration512ID + ".up.sql", migration512UpSHA, []string{
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration512Previous),
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration512Previous),
			"ERRCODE='P5120'", "repeat_threshold BETWEEN 2 AND 1000", "repeat_window BETWEEN 10 AND 600",
			"(repeat_threshold IS NULL) = (repeat_window IS NULL)",
		}},
		{migration512ID + ".down.sql", migration512DownSHA, []string{
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration512Version),
			"migration_id='" + migration512ID + "'", "ERRCODE='P5121'", "DROP COLUMN repeat_window",
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
