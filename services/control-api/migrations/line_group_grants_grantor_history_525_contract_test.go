package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 525 (NODE-N05: the grantor's line group grant history
// index for GET /v1/escalate/line-groups/grants). Everything that changes with
// a renumbering is here.
const (
	migration525Version         = 525
	migration525ID              = "525_line_group_grants_grantor_history"
	migration525PreviousID      = "524_market_feedback_notices"
	migration525PreviousUpSHA   = "9b349165f9c0451316debe7b14810d7c303b1c09a3fe9fc0bfa8c6a33f248db9"
	migration525PreviousDownSHA = "5349fa91a141170663cc04b9c4a1b2f6db94e81c9dcf51838aee337f1c0d8ec0"
	migration525UpSHA           = "dfb60716fa98ffc014c8d1c7888698eabbdb0727473b656658a7f7021fdcb446"
	migration525DownSHA         = "0fc826cdab2782fcf7dea35508d3e084811a6ddc724afa262b7273ae96552ee0"
)

func TestLineGroupGrantsGrantorHistory525Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration525ID + ".up.sql", migration525UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration525Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration525Version-1),
			"migration_id='" + migration525PreviousID + "'", migration525PreviousUpSHA, migration525PreviousDownSHA,
			"ERRCODE='P5250'", "ON node_line_group_grants (grantor_scope_id, created_at DESC, id DESC);",
		}},
		{migration525ID + ".down.sql", migration525DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration525Version),
			"migration_id='" + migration525ID + "'", "ERRCODE='P5251'",
			"DROP INDEX node_line_group_grants_grantor_history_525_idx;",
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
