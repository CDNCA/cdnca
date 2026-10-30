package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 394 (质量优选 strategy, probe round history, the
// quality switch reason) is a placeholder number (BATCH-PLUGIN 第 16 条
// reserves 400; the loader needs consecutive versions, so it sits on the
// integration head + 1). Everything that changes with the renumbering is here.
const (
	migration394Version         = 394
	migration394ID              = "394_aggregated_edge_quality"
	migration394PreviousID      = "393_acme_zero_match_cleanup"
	migration394PreviousUpSHA   = "6e30e3b5f94026497b7847c26dad04b5d64676c0c757c744384348fd197f05d9"
	migration394PreviousDownSHA = "54cb2a15504e7363ee8d179a33a7309b3c8d215ae225bb3cc78ae262ec5d7ae5"
	migration394UpSHA           = "31742813bd63915494f29db87db6d17dfd6f99da4474cb9ecb57fb0761da40c3"
	migration394DownSHA         = "0253b97951f615c5b604f5ab57d6ad9e7202f36108497d783e6dc5c9f1375fcb"
)

func TestAggregatedEdgeQuality394Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration394ID + ".up.sql", migration394UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration394Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration394Version-1),
			"migration_id='" + migration394PreviousID + "'", migration394PreviousUpSHA, migration394PreviousDownSHA,
			"ERRCODE='P3940'", "ADD COLUMN strategy text", "quality_min_interval_seconds", "quality_margin",
			"CREATE TABLE aggregated_edge_probe_rounds", "'quality', 'manual'",
		}},
		{migration394ID + ".down.sql", migration394DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration394Version),
			"migration_id='" + migration394ID + "'", "ERRCODE='P3941'", "ERRCODE='P3942'",
			"DROP TABLE aggregated_edge_probe_rounds", "DROP COLUMN strategy",
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
