package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 436 (ADR 0014 LIC-BAN-04/05; reserved number 441:
// renumber at merge), guarded on 428. Everything that changes with the
// renumbering is here.
const (
	migration436Version         = 436
	migration436PreviousVersion = 435
	migration436ID              = "436_installation_ban_state"
	migration436PreviousID      = "435_admin_self_approval"
	migration436PreviousUpSHA   = "be4c6888bfcf672c29a4a4a0b986d152285f6c946065bbfaf997737dbb11c0ac"
	migration436PreviousDownSHA = "d1a36297a2f979e16236409e532aa3e6544f6c83ec198211656734bf980b041b"
	migration436UpSHA           = "7e2f043d0fc778775acdd2c0d412baa46fd3fd49de1ec0fd3b849f21dc0f1c89"
	migration436DownSHA         = "a161099ea6b8bb3cfe31773f0652e29ba3fc008409d2867563b58af00ff0e5b8"
)

func TestInstallationBanState436Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration436ID + ".up.sql", migration436UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration436PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration436PreviousVersion),
			"migration_id='" + migration436PreviousID + "'", migration436PreviousUpSHA, migration436PreviousDownSHA,
			"ERRCODE='P4360'", "CREATE TABLE control_installation_ban_state", "CREATE TABLE installation_ban_node_state",
		}},
		{migration436ID + ".down.sql", migration436DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration436Version),
			"migration_id='" + migration436ID + "'", "ERRCODE='P4361'",
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
