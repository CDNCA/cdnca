package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 390 (HTTP 302 scheduling) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration390Version         = 390
	migration390ID              = "390_site_schedule302"
	migration390PreviousID      = "389_acme_ca_credentials"
	migration390PreviousUpSHA   = "7ed8cf7fc6ce984a50f5316ab13456c7bc23f89a6c6403351602723a36dcc044"
	migration390PreviousDownSHA = "0696ea87dff35b604c11a9c2325b52d057bd8f33e21ace16154421d6b1bbe226"
	migration390UpSHA           = "f805e5191361bd348ad96744b0df05ad42c329d6c1b9f64c0db5c31b46a66ac8"
	migration390DownSHA         = "74363990e8e80de3c076aa9a20c057a7143bf0143a5e3673ba173351e4fae76b"
)

func TestSiteSchedule302387Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration390ID + ".up.sql", migration390UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration390Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration390Version-1),
			"migration_id='" + migration390PreviousID + "'", migration390PreviousUpSHA, migration390PreviousDownSHA,
			"ERRCODE='P3900'", "CREATE TABLE site_schedule302_settings", "CREATE TABLE site_schedule302_write_requests",
			"nodes_schedule302_hostname_390_check", "CREATE TABLE node_schedule302_tables",
		}},
		{migration390ID + ".down.sql", migration390DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration390Version),
			"migration_id='" + migration390ID + "'", "ERRCODE='P3901'",
			"DROP TABLE site_schedule302_settings", "DROP CONSTRAINT nodes_schedule302_hostname_390_check",
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
