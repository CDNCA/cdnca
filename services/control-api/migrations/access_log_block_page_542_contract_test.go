package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Migration 542 (fix-decide1027b item 1: block_page joins the
// access_log_fields catalog). Its predecessor is 541, pinned by checksum.
const (
	migration542ID      = "542_access_log_block_page"
	migration542UpSHA   = "3acb1781eacc91450e79e21296045efb54f2cc1377c78120834b5fd2c8d8af03"
	migration542DownSHA = "816e34d5183c3c779bc6b19f50b49b5b7a62f298f0183021a059f224adbfbebe"
)

func TestAccessLogBlockPage542Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration542ID + ".up.sql", migration542UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 541", "(SELECT max(version) FROM schema_migrations) <> 541",
			"migration_id='" + migration541ID + "'", migration541UpSHA, migration541DownSHA, "ERRCODE='P5420'",
			"CREATE OR REPLACE FUNCTION system_configuration_v2_access_log_fields_is_valid",
		}},
		{migration542ID + ".down.sql", migration542DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 542", "migration_id='" + migration542ID + "'", "ERRCODE='P5421'",
			"? 'block_page'", "CREATE OR REPLACE FUNCTION system_configuration_v2_access_log_fields_is_valid",
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
	catalogOf := func(name string) string {
		raw, _ := FS.ReadFile(name)
		flat := strings.ReplaceAll(strings.Join(strings.Fields(string(raw)), " "), ", ", ",")
		_, rest, ok := strings.Cut(flat, "catalog text[] := ARRAY[")
		if !ok {
			t.Fatalf("%s has no catalog", name)
		}
		value, _, _ := strings.Cut(rest, "]")
		return value
	}
	// The database's catalog is edgeconfig.AccessLogFieldCatalog, in order.
	keys := make([]string, len(edgeconfig.AccessLogFieldCatalog))
	for index, field := range edgeconfig.AccessLogFieldCatalog {
		keys[index] = "'" + field.Key + "'"
	}
	if got, want := catalogOf(migration542ID+".up.sql"), strings.Join(keys, ","); got != want {
		t.Fatalf("542 catalog %s differs from edgeconfig.AccessLogFieldCatalog %s", got, want)
	}
	// Down restores 540's catalog.
	if got, want := catalogOf(migration542ID+".down.sql"), catalogOf(migration540ID+".up.sql"); got != want {
		t.Fatalf("542 down catalog %s, 540 %s", got, want)
	}
}
