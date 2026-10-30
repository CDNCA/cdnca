package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 547 (fix-nodeipgeo): automatic node IP 归属 resolutions, the
// manual field list and the node locations mark. Its guard pins 546's
// checksums (fix-ticket2); everything that changes with the number is here.
const (
	migration547Version         = 547
	migration547PreviousVersion = 546
	migration547PreviousID      = "546_ticket_notification_choices"
	migration547PreviousUpSHA   = "fc87066c830bf3d307312bfcbacb9e12911f551541a4e03f14caaa18ae7aa554"
	migration547PreviousDownSHA = "ede77a7148f0c967071a93d0a3ffa9404929f754e4cc9c6af3e8cc8a9ae9ad85"
	migration547ID              = "547_node_ip_location_resolution"
)

func TestNodeIPLocationResolution547Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration547ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration547PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration547PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration547PreviousVersion),
			"migration_id='" + migration547PreviousID + "'",
			"checksum_sha256='" + migration547PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration547PreviousDownSHA + "'",
			"ERRCODE='P5470'", "CREATE TABLE node_ip_location_resolutions",
			"REFERENCES nodes(id) ON DELETE CASCADE", "nodes_ip_location_manual_547_check",
			"ADD COLUMN locations_sha256 bytea",
		}},
		{migration547ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration547Version),
			"migration_id='" + migration547ID + "'", "ERRCODE='P5471'",
			"DROP COLUMN locations_sha256", "DROP TABLE node_ip_location_resolutions",
			"management_settings - 'ip_location_manual'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	// Once 546 is in the tree the guard must pin its actual checksums.
	for suffix, want := range map[string]string{".up.sql": migration547PreviousUpSHA, ".down.sql": migration547PreviousDownSHA} {
		raw, err := FS.ReadFile(migration547PreviousID + suffix)
		if err != nil {
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, 547 guard pins %s", migration547PreviousID, suffix, got, want)
		}
	}
}
