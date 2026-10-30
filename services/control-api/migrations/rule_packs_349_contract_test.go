package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 349 (rule packs, enablement overrides, site
// security mounts) is a placeholder number: the merge renumbers it after the
// head it lands on. Everything that changes with the renumbering is here.
const (
	migration349Version         = 349
	migration349ID              = "349_rule_packs"
	migration349PreviousID      = "348_node_deployment_timeouts"
	migration349PreviousUpSHA   = "1073378383d2e63d4858913f637c54be738e2af70f73b0332e1176ed9f8b9a01"
	migration349PreviousDownSHA = "4066592c54f6f32b66fcd091d2c377e3cc11519d2c6c41c5cfec555cd57f2214"
	migration349UpSHA           = "ba2acf69a0296766ac6d7538824677d784bf39c536abcca884b041e4a5aab0a8"
	migration349DownSHA         = "cae1167cd408935a65269841290108990acb984ee6e428bb368147ab82fadb75"
)

func TestRulePacks349Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration349ID + ".up.sql", migration349UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration349Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration349Version-1),
			"migration_id='" + migration349PreviousID + "'", migration349PreviousUpSHA, migration349PreviousDownSHA,
			"ERRCODE='P3490'", "CREATE TABLE rule_packs", "CREATE TABLE rule_pack_artifacts",
			"CREATE TABLE rule_pack_enablements", "NULLS NOT DISTINCT", "CREATE TABLE site_security_mounts",
			"ON DELETE RESTRICT",
		}},
		{migration349ID + ".down.sql", migration349DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration349Version),
			"migration_id='" + migration349ID + "'", "ERRCODE='P3491'", "DROP TABLE rule_packs",
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
