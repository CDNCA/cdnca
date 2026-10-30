package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 508: package traffic over the
// limit stops the subscription's L4 forwards too. Reserved number 506; 508
// follows 507 (the merge renumbered it from 493).
const (
	migration508Version         = 508
	migration508PreviousVersion = 507
	migration508ID              = "508_package_traffic_stream_suspensions"
	migration508PreviousID      = migration507ID
	migration508PreviousUpSHA   = migration507UpSHA
	migration508PreviousDownSHA = migration507DownSHA
	migration508UpSHA           = "55cca49a9f2d6f3b6e2628cba132b23cf3ecf6b1e362ee0553ee69927fc30b04"
	migration508DownSHA         = "bf804a262b71532ae58794ff6114f99af92da76dcf8016d6556d1cf4718023c0"
)

func TestPackageTrafficStreamSuspensions508Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration508ID + ".up.sql", migration508UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration508PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration508PreviousVersion),
			"migration_id='" + migration508PreviousID + "'", migration508PreviousUpSHA, migration508PreviousDownSHA,
			"ERRCODE='P5080'", "ERRCODE='P5081'",
			"CREATE TABLE package_traffic_stream_suspensions", "REFERENCES l4_forwards(id) ON DELETE RESTRICT",
			"ON package_traffic_stream_suspensions (stream_id) WHERE recovered_at IS NULL",
			"BEFORE UPDATE OR DELETE ON package_traffic_stream_suspensions",
		}},
		{migration508ID + ".down.sql", migration508DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration508Version),
			"migration_id='" + migration508ID + "'", "ERRCODE='P5082'", "ERRCODE='P5083'",
			"DROP TABLE package_traffic_stream_suspensions",
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
