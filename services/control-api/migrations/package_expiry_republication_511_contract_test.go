package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 511: system republication trigger
// package_expiry and the expiry sweep marks. Branch placeholder 499, renumbered
// to 511 behind 510 at merge. Everything that changes with the number is here.
const (
	migration511Version         = 511
	migration511PreviousVersion = 510
	migration511ID              = "511_package_expiry_republication"
	migration511PreviousID      = "510_escalate_blackhole_drop_confirmed"
	migration511PreviousUpSHA   = "00eb12bd5ca291086208f1a244ef2c1e659259cccced2fcaac87547f6b1276f7"
	migration511PreviousDownSHA = "ad399589119e104d5bb31d2b0f8f30f3bb6c84d044a4d39838cf5ee5c9759090"
	migration511UpSHA           = "0f6f4f4a3a7484a73570d08dd2ab4a09c9596f94e25b57b2fb46a03fcd56dff2"
	migration511DownSHA         = "9fd94c9c65c0314c4f567b44f18bf45e5f964f21856fd0220a48e193dec87f58"
)

func TestPackageExpiryRepublication511Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration511ID + ".up.sql", migration511UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration511PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration511PreviousVersion),
			"migration_id='" + migration511PreviousID + "'", migration511PreviousUpSHA, migration511PreviousDownSHA,
			"ERRCODE='P5110'", "cardinality(triggers) BETWEEN 1 AND 19", "'attack_escalation',\n            'package_expiry']::text[]",
			"'attack_escalation', 'package_expiry'));", "CREATE TABLE package_expiry_republication_marks",
		}},
		{migration511ID + ".down.sql", migration511DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration511Version),
			"migration_id='" + migration511ID + "'", "ERRCODE='P5111'", "ERRCODE='P5112'",
			"DROP TABLE package_expiry_republication_marks", "cardinality(triggers) BETWEEN 1 AND 18",
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
