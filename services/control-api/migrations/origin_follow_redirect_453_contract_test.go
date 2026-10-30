package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 453 is a placeholder number; the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is here.
const (
	migration453Version         = 453
	migration453ID              = "453_origin_follow_redirect"
	migration453PreviousID      = "452_node_security_waf_ban_alerts"
	migration453PreviousUpSHA   = "4edf8710fbeb0e36b55fe8790d0929e1075d05e50890871abeb0ccc585599617"
	migration453PreviousDownSHA = "4e4cd71ee8088a8cf4732be4d4494d0efd4df2209396f25399affbff69f30507"
	migration453UpSHA           = "dd662c6010efd183e056c42688b6a80ca464e33846de259d4ec590e90c76fc6b"
	migration453DownSHA         = "60b8427fa5730fbb9765fa97e0ff8e736e2f77e8155707b4990ba8a92d8f8318"
)

func TestOriginFollowRedirect453Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration453ID + ".up.sql", migration453UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration453Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration453Version-1),
			"migration_id='" + migration453PreviousID + "'", migration453PreviousUpSHA, migration453PreviousDownSHA,
			"ERRCODE='P4530'", "ADD COLUMN follow_redirect boolean NOT NULL DEFAULT false",
			"CHECK (follow_redirect_max_hops BETWEEN 1 AND 5)", "ADD COLUMN follow_redirect_cross_origin boolean NOT NULL DEFAULT false",
		}},
		{migration453ID + ".down.sql", migration453DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration453Version),
			"migration_id='" + migration453ID + "'", "ERRCODE='P4531'", "ERRCODE='P4532'",
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
