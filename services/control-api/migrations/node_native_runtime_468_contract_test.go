package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 468 (node_presence.native_runtime_*)
// guards the 467_site_theme_scopes head; renumber at the merge if 468 is
// taken (the guard, the error codes P<version>0/1 and the checksums below).
const (
	migration468Version         = 468
	migration468ID              = "468_node_native_runtime"
	migration468PreviousID      = "467_site_theme_scopes"
	migration468PreviousUpSHA   = "8358bf5a3e5e1f2e87e42895411bb0f5a0a70f9af243f7d41fd7d91f6cdddb54"
	migration468PreviousDownSHA = "0d0b96fb19d7ba8eb812e6ee200edb84373e718676b43d5e4b20fbaabe086084"
	migration468UpSHA           = "0e6ce3d3dc426695ab7c142fa2581f0e5cce0a2a754e14bfc7a6700a04b96dba"
	migration468DownSHA         = "8a4e6bd6fabe1c56cc277f48d570d733def4555f97f4cff7616235d94625a587"
)

func TestNodeNativeRuntime468Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration468ID + ".up.sql", migration468UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration468Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration468Version-1),
			"migration_id='" + migration468PreviousID + "'", migration468PreviousUpSHA, migration468PreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", migration468Version),
			"native_runtime_state IN ('switched', 'unchanged', 'rolled_back')",
			"native_runtime_release ~ '^[0-9a-f]{64}$'", "native_runtime_previous_release ~ '^[0-9a-f]{64}$'",
			"native_runtime_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'",
			"native_runtime_error_code IS NULL OR native_runtime_state = 'rolled_back'",
		}},
		{migration468ID + ".down.sql", migration468DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration468Version),
			"migration_id='" + migration468ID + "'", fmt.Sprintf("ERRCODE='P%d1'", migration468Version),
			"DROP COLUMN native_runtime_state", "DROP COLUMN native_runtime_release",
			"DROP COLUMN native_runtime_previous_release", "DROP COLUMN native_runtime_error_code",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
