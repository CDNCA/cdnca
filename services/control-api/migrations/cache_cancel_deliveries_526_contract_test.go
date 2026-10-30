package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 526 (CACHE-ADD-07: per node cache cancel deliveries;
// 527 was reserved, written as 526 for the contiguous loader).
// Everything that changes with a renumbering is here.
const (
	migration526Version         = 526
	migration526ID              = "526_cache_cancel_deliveries"
	migration526PreviousID      = "525_line_group_grants_grantor_history"
	migration526PreviousUpSHA   = "dfb60716fa98ffc014c8d1c7888698eabbdb0727473b656658a7f7021fdcb446"
	migration526PreviousDownSHA = "0fc826cdab2782fcf7dea35508d3e084811a6ddc724afa262b7273ae96552ee0"
	migration526UpSHA           = "a8072a592d876d9a710dc0b9efd3c6e3ec1805897c41ce58e40e78c9840f6b0b"
	migration526DownSHA         = "13d617fc73f2411420a930185aabd38d5059fcf7fd1f23e6ceaaaa5fcbf3a9b0"
)

func TestCacheCancelDeliveries526Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration526ID + ".up.sql", migration526UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration526Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration526Version-1),
			"migration_id='" + migration526PreviousID + "'", migration526PreviousUpSHA, migration526PreviousDownSHA,
			"ERRCODE='P5260'", "CREATE TABLE cache_operation_cancel_deliveries",
			"state IN ('pending', 'cancelled', 'completed', 'unresponsive', 'unsupported')",
			"REFERENCES cache_operation_node_attempts(scope_id, operation_id, node_id, attempt) ON DELETE CASCADE",
		}},
		{migration526ID + ".down.sql", migration526DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration526Version),
			"migration_id='" + migration526ID + "'", "ERRCODE='P5261'", "ERRCODE='P5262'",
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
