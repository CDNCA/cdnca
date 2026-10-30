package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 418 (origin levels, failback mode, probe
// and failover state, system trigger origin_failover, two notification
// events) is a placeholder number: BATCH-PLUGIN 第 18 条 reserves 422, the
// merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is here.
const (
	migration418Version         = 418
	migration418ID              = "418_origin_failover"
	migration418PreviousID      = "417_rule_pack_mount_suspensions"
	migration418PreviousUpSHA   = "080ae0dd3d3c77faf5c4c98073f7e6b1e7bd01cbe47bcb2da895b74ec366d4ca"
	migration418PreviousDownSHA = "6d814a39ae6484c1691644cb8ab8978a46f11bfd08098101b40e256bc239405a"
	migration418UpSHA           = "d4ed3c4729f80045e344c73b1b1ddb118b79828491efdab96ecac060eaad4bc8"
	migration418DownSHA         = "81f58c2b98fc58dc33b1e42874b00e83edde3fb8177d97cc0ce9121fe0e04ead"
)

func TestOriginFailover418Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration418ID + ".up.sql", migration418UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration418Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration418Version-1),
			"migration_id='" + migration418PreviousID + "'", migration418PreviousUpSHA, migration418PreviousDownSHA,
			"ERRCODE='P4180'", "BETWEEN 1 AND 15", "'origin_auth_published', 'origin_failover']::text[]",
			"UPDATE site_origins SET level = 1 WHERE backup;", "count(*) FILTER (WHERE enabled AND level = 0)",
		}},
		{migration418ID + ".down.sql", migration418DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration418Version),
			"migration_id='" + migration418ID + "'", "ERRCODE='P4181'", "ERRCODE='P4182'", "BETWEEN 1 AND 14",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
