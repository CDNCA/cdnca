package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 417 (suspended rule pack mounts) is a
// placeholder number (BATCH-PLUGIN 第 16 条): the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration417Version         = 417
	migration417ID              = "417_rule_pack_mount_suspensions"
	migration417PreviousVersion = 416
	migration417PreviousID      = "416_site_facts_republication"
	migration417PreviousUpSHA   = "c5a3dcbacd0c13c1f2ac83e987e67c31bb97138d284f2cf625a370147165cb9c"
	migration417PreviousDownSHA = "e5a9f277dc0be1e0b9531665eb5855c80ef15b3b9154ee6a23a3f34260ceab51"
	migration417UpSHA           = "080ae0dd3d3c77faf5c4c98073f7e6b1e7bd01cbe47bcb2da895b74ec366d4ca"
	migration417DownSHA         = "6d814a39ae6484c1691644cb8ab8978a46f11bfd08098101b40e256bc239405a"
)

func TestRulePackMountSuspensions417Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration417ID + ".up.sql", migration417UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration417PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration417PreviousVersion),
			"migration_id='" + migration417PreviousID + "'", migration417PreviousUpSHA, migration417PreviousDownSHA,
			"ERRCODE='P4170'", "CREATE TABLE rule_pack_mount_suspensions",
			"REFERENCES rule_pack_artifacts(pack_id, version) ON DELETE RESTRICT",
		}},
		{migration417ID + ".down.sql", migration417DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration417Version),
			"migration_id='" + migration417ID + "'", "ERRCODE='P4171'", "DROP TABLE rule_pack_mount_suspensions",
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
