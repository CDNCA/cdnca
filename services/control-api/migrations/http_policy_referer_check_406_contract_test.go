package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 406 (hotlink protection referer_check) is a
// placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is in this block.
const (
	geWAFMigration406Version         = 406
	geWAFMigration406ID              = "406_http_policy_referer_check"
	geWAFMigration406PreviousID      = geWAFMigration405ID
	geWAFMigration406PreviousUpSHA   = geWAFMigration405UpSHA
	geWAFMigration406PreviousDownSHA = geWAFMigration405DownSHA
	geWAFMigration406UpSHA           = "bf1d4b29b1422ac549d95266875ffd6cd4c12854830d8623b7cdc188606d7675"
	geWAFMigration406DownSHA         = "7949e0b3c479c53c23bd0295df87ef44ee8650f62bea6b4c28cbf09c6b40f86f"
)

func TestHTTPPolicyRefererCheck406Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{geWAFMigration406ID + ".up.sql", geWAFMigration406UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration406Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", geWAFMigration406Version-1),
			"migration_id='" + geWAFMigration406PreviousID + "'", geWAFMigration406PreviousUpSHA, geWAFMigration406PreviousDownSHA,
			"ERRCODE='P4060'", "http_policy_referer_check_valid_406(document -> 'referer_check')",
		}},
		{geWAFMigration406ID + ".down.sql", geWAFMigration406DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration406Version),
			"migration_id='" + geWAFMigration406ID + "'", "ERRCODE='P4061'", "ERRCODE='P4062'",
			"DROP FUNCTION http_policy_referer_check_valid_406(jsonb)",
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
