package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Every number the merge renumbering touches is here: the
// version, the previous head it guards on, and the script checksums.
const (
	lateJoinVersion        = 304
	lateJoinID             = "304_announcement_late_join_recipients"
	lateJoinPreviousID     = "303_domain_trust"
	lateJoinPreviousUpSHA  = "ab0677edaf2c2db45e8b7f7d764a6ff5d766911f9de519209777363ccb876153"
	lateJoinPreviousDownSH = "7c851de89b64a91c45efe4acd9e4e89387774a69ac1daf67bd6a87bf1a522b9a"
	lateJoinUpSHA          = "ed7e177bd4e9528f777771652491ee6f341b0aeeba6fdf41887d34946413c7b0"
	lateJoinDownSHA        = "8bd6a2fbff34ea7c3c0dfd1e073c2db18bb3ee032b2c303fe71ff1dec86a92b7"
)

func TestAnnouncementLateJoin304Contract(t *testing.T) {
	previous := lateJoinVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{lateJoinID + ".up.sql", lateJoinUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + lateJoinPreviousID + "'",
			"checksum_sha256='" + lateJoinPreviousUpSHA + "'",
			"down_checksum_sha256='" + lateJoinPreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", lateJoinVersion),
			"current_setting('cdnca.announcement_late_join', true) = 'on'", "pg_trigger_depth() >= 2",
			"version.audience_mode = 'all'", "(root.audience->>'all_tenants')::boolean",
			"AFTER INSERT OR UPDATE OF status ON memberships",
		}},
		{lateJoinID + ".down.sql", lateJoinDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", lateJoinVersion),
			"migration_id='" + lateJoinID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", lateJoinVersion),
			"DROP FUNCTION announcement_late_join_304()",
			"'recipient snapshots may only be created during publication'",
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
