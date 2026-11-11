package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// Server-Timing 响应头 (651) guards the 650 head (certificate publication
// redelivery recovery). Every number tied to the chain is here.
const (
	serverTimingVersion         = 651
	serverTimingID              = "651_site_server_timing"
	serverTimingPreviousID      = "650_certificate_publication_redelivery_recovery"
	serverTimingPreviousUpSHA   = "040422c0fcc1978e51a07ed4102076d3c84ccb1ea8e0bc23e22bf11295db2d6a"
	serverTimingPreviousDownSHA = "427f8b8777889e6fbb06f341b1ffc465332d764b70caa1c333d047134194cc38"
	serverTimingUpSHA           = "983b37fb8e0958e0595f2b96393028d7b002ec42d77124bed4233651ae75f736"
	serverTimingDownSHA         = "e82018d4d9b827703426225ac7a6215ff662f7799e486e9447ffe3ea7544840b"
)

func TestSiteServerTiming651Contract(t *testing.T) {
	previous := serverTimingVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{serverTimingID + ".up.sql", serverTimingUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + serverTimingPreviousID + "'",
			"checksum_sha256='" + serverTimingPreviousUpSHA + "'",
			"down_checksum_sha256='" + serverTimingPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", serverTimingVersion),
			"ADD COLUMN server_timing boolean NOT NULL DEFAULT false",
		}},
		{serverTimingID + ".down.sql", serverTimingDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", serverTimingVersion),
			"migration_id='" + serverTimingID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", serverTimingVersion),
			"DROP COLUMN server_timing",
		}},
	} {
		raw, err := controlmigrations.FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		text := string(raw)
		for _, required := range script.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "ALTER TABLE"); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
