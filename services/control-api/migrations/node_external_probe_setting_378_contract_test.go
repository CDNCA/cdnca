package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 378 (probe-only nodes by default) is a
// placeholder number; everything the renumbering changes is in this block.
const (
	migration378Version         = 378
	migration378ID              = "378_node_external_probe_setting"
	migration378PreviousID      = "377_ddos_protection"
	migration378PreviousUpSHA   = "ad1e06fdd563af1c6a0aff2f2f168d2131662bb62104a6af4bba782fb88ebcf1"
	migration378PreviousDownSHA = "60f1f4da452c625a07765a5fb88af4e2fe683d6f8e4a57aeaa14f24b0038fdbf"
	migration378UpSHA           = "0a8f26000686f9e8af3b740ec8ec2c5a416d244ed51e88e2b6ffa9b8e5e2f8ae"
	migration378DownSHA         = "8e4181c14a12722f3b5c655dcfbb47aba48876b49f7a39ad8e35d949b68dea4b"
)

func TestNodeExternalProbeSetting378Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration378ID + ".up.sql", migration378UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration378Version-1),
			"migration_id='" + migration378PreviousID + "'", migration378PreviousUpSHA, migration378PreviousDownSHA,
			"ERRCODE='P3780'", "nodes_management_settings_external_probe_378_check",
		}},
		{migration378ID + ".down.sql", migration378DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration378Version),
			"migration_id='" + migration378ID + "'", "ERRCODE='P3781'",
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
