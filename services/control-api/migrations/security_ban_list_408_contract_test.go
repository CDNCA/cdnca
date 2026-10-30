package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 408 (the security ban list library) is a
// placeholder number: the merge renumbers it after the head it lands on and
// points the guard at the real previous version (written against the
// integration head 391_http_policy_regex_rules). Everything that changes
// with the renumbering is in this block.
const (
	geWAFMigration408Version         = 408
	geWAFMigration408PreviousVersion = geWAFMigration407Version
	geWAFMigration408ID              = "408_security_ban_list"
	geWAFMigration408PreviousID      = geWAFMigration407ID
	geWAFMigration408PreviousUpSHA   = geWAFMigration407UpSHA
	geWAFMigration408PreviousDownSHA = geWAFMigration407DownSHA
	geWAFMigration408UpSHA           = "2930704b02b72ecf91078d776b2f59fb92cf538dec68e94f7284d3dbfaf52690"
	geWAFMigration408DownSHA         = "02e04ab4134098bbd3f7de2faadba530b95d034f0508f783398f356e5c497e49"
)

func TestSecurityBanList408Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{geWAFMigration408ID + ".up.sql", geWAFMigration408UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration408PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", geWAFMigration408PreviousVersion),
			"migration_id='" + geWAFMigration408PreviousID + "'", geWAFMigration408PreviousUpSHA, geWAFMigration408PreviousDownSHA,
			"ERRCODE='P4080'", "CREATE TABLE security_ban_entries", "CREATE TABLE security_ban_write_requests",
			"CREATE TABLE security_ban_sync_cursor", "CREATE TABLE security_ban_node_state",
		}},
		{geWAFMigration408ID + ".down.sql", geWAFMigration408DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration408Version),
			"migration_id='" + geWAFMigration408ID + "'", "ERRCODE='P4081'", "ERRCODE='P4082'",
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
