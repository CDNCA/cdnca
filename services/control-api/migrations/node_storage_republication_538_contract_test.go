package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 538 (fix-nodesettings): system republication trigger
// node_storage and the node storage mark. Its guard pins 537's checksums.
// Everything that changes with the number is here.
const (
	migration538Version         = 538
	migration538PreviousVersion = 537
	migration538PreviousID      = "537_certificate_asset_auto_renew"
	migration538ID              = "538_node_storage_republication"
	migration538UpSHA           = "c66c5d1f086777f9f5da89be7e4059c389a97e6df68ee9681f657b5c767a8617"
	migration538DownSHA         = "2ad500fef470fd36c6219f6882fcf69b032eb8185bf896d2d20a25be6fa11fbb"
)

func TestNodeStorageRepublication538Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration538ID + ".up.sql", migration538UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration538PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration538PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration538PreviousVersion),
			"migration_id='" + migration538PreviousID + "'",
			"checksum_sha256='" + sha256File(t, migration538PreviousID+".up.sql") + "'",
			"down_checksum_sha256='" + sha256File(t, migration538PreviousID+".down.sql") + "'",
			"ERRCODE='P5380'", "cardinality(triggers) BETWEEN 1 AND 20", "'package_expiry', 'node_storage']::text[]",
			"'package_expiry', 'node_storage'));", "ADD COLUMN storage_sha256 bytea",
		}},
		{migration538ID + ".down.sql", migration538DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration538Version),
			"migration_id='" + migration538ID + "'", "ERRCODE='P5381'", "ERRCODE='P5382'",
			"DROP COLUMN storage_sha256", "cardinality(triggers) BETWEEN 1 AND 19",
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

func sha256File(t *testing.T, name string) string {
	t.Helper()
	raw, err := FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
