package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (307 placeholder). Every number the merge renumbering touches is here: the
// version, the previous head it guards on, and the script checksums.
const (
	originKeepaliveVersion         = 307
	originKeepaliveID              = "307_site_origin_keepalive"
	originKeepalivePreviousID      = "306_security_activation_capability_waits"
	originKeepalivePreviousUpSHA   = "12ac6e3078913063754f16f2b97d8e9f6a5a3b518011fc363e77569f6ccc4242"
	originKeepalivePreviousDownSHA = "bbdfce794d3382d532494f7d71b6a7bc2179cbb30e8227eb844b0b388d753b68"
	originKeepaliveUpSHA           = "64af8a7720f0d553a0e63c6101c19729c6433a5df4996c67b1b3cbe95e9299b1"
	originKeepaliveDownSHA         = "fe0466749f4fb83f1d655a053c65f86dda4aa33d38c51fd512ac84ca711e456a"
)

func TestSiteOriginKeepalive307Contract(t *testing.T) {
	previous := originKeepaliveVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{originKeepaliveID + ".up.sql", originKeepaliveUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + originKeepalivePreviousID + "'",
			"checksum_sha256='" + originKeepalivePreviousUpSHA + "'",
			"down_checksum_sha256='" + originKeepalivePreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", originKeepaliveVersion),
			"ADD COLUMN keepalive_enabled boolean NOT NULL DEFAULT true",
			"ADD COLUMN keepalive_idle_timeout_ms integer NOT NULL DEFAULT 60000",
			"CHECK (keepalive_idle_timeout_ms BETWEEN 1000 AND 300000)",
		}},
		{originKeepaliveID + ".down.sql", originKeepaliveDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", originKeepaliveVersion),
			"migration_id='" + originKeepaliveID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", originKeepaliveVersion),
			"DROP COLUMN keepalive_idle_timeout_ms", "DROP COLUMN keepalive_enabled",
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
