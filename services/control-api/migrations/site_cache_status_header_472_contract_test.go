package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (472, BATCH 81; guards the integration head 471
// theme block pages). Every number the merge renumbering touches is here.
const (
	cacheStatusHeaderVersion         = 472
	cacheStatusHeaderID              = "472_site_cache_status_header"
	cacheStatusHeaderPreviousID      = "471_theme_block_pages"
	cacheStatusHeaderPreviousUpSHA   = "e660fa014659b1112cad7a67211dba329c2ae3faf13acb09ff32be6c48f54b3e"
	cacheStatusHeaderPreviousDownSHA = "4bd9ad669a400c8026d74a679e2213f977312a7244f44ff6a8d31f7de22ee126"
	cacheStatusHeaderUpSHA           = "bfa4893110282f6df2a541a7f15f92ec631db93e5ec27c8e246ef3e897a0a0e2"
	cacheStatusHeaderDownSHA         = "ff250fffa7d109a2cfa61a74c0141669fea2587c97c987bac387204879b8ea6f"
)

func TestSiteCacheStatusHeader472Contract(t *testing.T) {
	previous := cacheStatusHeaderVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{cacheStatusHeaderID + ".up.sql", cacheStatusHeaderUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + cacheStatusHeaderPreviousID + "'",
			"checksum_sha256='" + cacheStatusHeaderPreviousUpSHA + "'",
			"down_checksum_sha256='" + cacheStatusHeaderPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", cacheStatusHeaderVersion),
			"ADD COLUMN cache_status_header boolean NOT NULL DEFAULT true",
		}},
		{cacheStatusHeaderID + ".down.sql", cacheStatusHeaderDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", cacheStatusHeaderVersion),
			"migration_id='" + cacheStatusHeaderID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", cacheStatusHeaderVersion),
			"DROP COLUMN cache_status_header",
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
