package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (356 placeholder; guards the integration head 355). Every
// number the merge renumbering touches is here: the version, the previous head
// it guards on, and the script checksums.
const (
	cacheSharedVersion         = 356
	cacheSharedID              = "356_site_cache_shared_across_domains"
	cacheSharedPreviousID      = "355_site_quick_block_overrides"
	cacheSharedPreviousUpSHA   = "907199b211564f0dfd565251048151c164bce43679aef7d7b223e754961e9e4d"
	cacheSharedPreviousDownSHA = "f320bb5d52d5e56b7da375d0f3a392b8893e5caa0b22c53a5a01222279eb16a7"
	cacheSharedUpSHA           = "dd69f72578e5a6d56f3e3cf5eced55a2ceb8e99700426077439240db0bf0accc"
	cacheSharedDownSHA         = "4eff66a3efa731a8504eb4781175c71c4b18229eccffd9b4e75fefcf2c991301"
)

func TestSiteCacheSharedAcrossDomains356Contract(t *testing.T) {
	previous := cacheSharedVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{cacheSharedID + ".up.sql", cacheSharedUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + cacheSharedPreviousID + "'",
			"checksum_sha256='" + cacheSharedPreviousUpSHA + "'",
			"down_checksum_sha256='" + cacheSharedPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", cacheSharedVersion),
			"ADD COLUMN cache_shared_across_domains boolean NOT NULL DEFAULT false",
		}},
		{cacheSharedID + ".down.sql", cacheSharedDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", cacheSharedVersion),
			"migration_id='" + cacheSharedID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", cacheSharedVersion),
			"DROP COLUMN cache_shared_across_domains",
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
