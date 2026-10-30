package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 572 (fix-cfundo, 占位): the undo of a Cloudflare migrate
// (restoring/restored, the supply that took the hostname over). Its guard
// pins 555's checksums; everything that changes with the number is here.
const (
	migration572Version         = 572
	migration572PreviousVersion = 571
	migration572PreviousID      = "571_node_line_backup_states"
	migration572PreviousUpSHA   = "338092a939360bd9f3e15e5acc20b7d29bf8fb6119dece51262360df4d073e75"
	migration572PreviousDownSHA = "c4b307ac6ad2674f8b30fb439559e071729a8457d8906f0d62166aae726e3b64"
	migration572ID              = "572_aggregated_edge_migrate_restore"
)

func TestAggregatedEdgeMigrateRestore572Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration572ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration572PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration572PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration572PreviousVersion),
			"migration_id='" + migration572PreviousID + "'",
			"checksum_sha256='" + migration572PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration572PreviousDownSHA + "'",
			"ERRCODE='P5720'", "'restoring', 'restored'", "ADD COLUMN supply_id uuid REFERENCES site_supplies(id)",
			"binding IN ('', 'created', 'reused')", "(state = 'restored') = (restored_at IS NOT NULL)",
		}},
		{migration572ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration572Version),
			"migration_id='" + migration572ID + "'", "ERRCODE='P5721'",
			"DROP COLUMN restored_at", "state IN ('planned', 'applied', 'failed', 'cancelled', 'superseded')",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration572PreviousUpSHA, ".down.sql": migration572PreviousDownSHA} {
		raw, err := FS.ReadFile(migration572PreviousID + suffix)
		if err != nil {
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, 572 guard pins %s", migration572PreviousID, suffix, got, want)
		}
	}
}
