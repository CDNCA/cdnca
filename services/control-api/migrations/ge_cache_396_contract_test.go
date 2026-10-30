package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 396 is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration396Version         = 396
	migration396ID              = "396_ge_cache"
	migration396PreviousID      = "395_ddos_tcp_flags"
	migration396PreviousUpSHA   = "a54c3be15b6174c90bd92234baa891f4f80eb2131eba6b64f20d6daddd55ba13"
	migration396PreviousDownSHA = "b48d953879faa9b83bf24642ea7981dc318291ec47a3fda4375ab31ba6d21817"
	migration396UpSHA           = "1ad8fba779a1a603581b1074c5f48f90ca35d0e03ee2f6ec0cac864764878d90"
	migration396DownSHA         = "03e4886921448fd0c46dfbcafbb0fd723c53649a67ed672c7f271cd34b4225ce"
)

func TestGECache396Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration396ID + ".up.sql", migration396UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration396Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration396Version-1),
			"migration_id='" + migration396PreviousID + "'", migration396PreviousUpSHA, migration396PreviousDownSHA,
			"ERRCODE='P3960'", "ADD COLUMN extensions jsonb",
			"definition.extensions IS DISTINCT FROM NEW.extensions", "ADD COLUMN auto_nodes",
			"ADD COLUMN parent_operation_id", "'proxy_cache_min_free_bytes'",
		}},
		{migration396ID + ".down.sql", migration396DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration396Version),
			"migration_id='" + migration396ID + "'", "ERRCODE='P3961'",
			"'proxy_cache_dir'",
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
	up, _ := FS.ReadFile(migration396ID + ".up.sql")
	if strings.Contains(string(up), "'proxy_cache_dir'") {
		t.Error("396 up still accepts proxy_cache_dir")
	}
}
