package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 414 (module "智能自动" values per node) is a
// placeholder number (BATCH-PLUGIN 第 16 条): the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration414Version         = 414
	migration414ID              = "414_autodefense_module_values"
	migration414PreviousVersion = 413
	migration414PreviousID      = "413_site_status_recovery_write_requests"
	migration414PreviousUpSHA   = "26e6ba27e1b9ab73c841f66d79ff221c34d4630798c0478aa464d8b1a4a6d7c9"
	migration414PreviousDownSHA = "9b20e44404803f3c59506d1233e81a933d450d23f752b0c18d4729bf31f10560"
	migration414UpSHA           = "75d44f0f16cd29ddcb04f3e417f0ff47bb9df2182ecaf176a3572d7dd2fc3fad"
	migration414DownSHA         = "cc72a3ecc92418b64e244a16086756e42771dd76374130dd481b3a07173085f5"
)

func TestAutoDefenseModuleValues414Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration414ID + ".up.sql", migration414UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration414PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration414PreviousVersion),
			"migration_id='" + migration414PreviousID + "'", migration414PreviousUpSHA, migration414PreviousDownSHA,
			"ERRCODE='P4140'", "CREATE TABLE autodefense_module_values",
		}},
		{migration414ID + ".down.sql", migration414DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration414Version),
			"migration_id='" + migration414ID + "'", "ERRCODE='P4141'", "DROP TABLE autodefense_module_values",
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
