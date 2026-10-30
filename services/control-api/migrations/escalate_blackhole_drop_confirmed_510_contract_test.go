package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 510: the blackhole notice gets its "nodes confirmed
// the drop" stage. Branch placeholder 501; the merge renumbered it to 510 behind 509.
const (
	migration510Version         = 510
	migration510PreviousVersion = 509
	migration510ID              = "510_escalate_blackhole_drop_confirmed"
	migration510PreviousID      = migration509ID
	migration510PreviousUpSHA   = migration509UpSHA
	migration510PreviousDownSHA = migration509DownSHA
	migration510UpSHA           = "00eb12bd5ca291086208f1a244ef2c1e659259cccced2fcaac87547f6b1276f7"
	migration510DownSHA         = "ad399589119e104d5bb31d2b0f8f30f3bb6c84d044a4d39838cf5ee5c9759090"
)

func TestEscalateBlackholeDropConfirmed510Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration510ID + ".up.sql", migration510UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration510PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration510PreviousVersion),
			"migration_id='" + migration510PreviousID + "'", migration510PreviousUpSHA, migration510PreviousDownSHA,
			"ERRCODE='P5100'", "'security.escalate.blackhole_drop_confirmed', true, true, true, 1, 1, true, true, false",
			"('security.escalate.blackhole.zh-cn', 2, 'email'", "('security.escalate.blackhole_drop_confirmed.zh-cn', 1, 'sms'",
			"('security.escalate.blackhole_drop_confirmed.zh-cn', 1, 'email'", "ARRAY['domain','occurred_at','confirmed_at','nodes','limited']",
		}},
		{migration510ID + ".down.sql", migration510DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration510Version),
			"migration_id='" + migration510ID + "'", "ERRCODE='P5101'", "ERRCODE='P5102'",
			"DELETE FROM notification_event_policies WHERE event_type = 'security.escalate.blackhole_drop_confirmed'",
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
