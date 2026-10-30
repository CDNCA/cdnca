package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 377 (node DDoS protection system configuration
// category) is a placeholder number: the merge renumbers it after the head it
// lands on. Everything that changes with the renumbering is in this block.
const (
	migration377Version         = 377
	migration377ID              = "377_ddos_protection"
	migration377PreviousID      = "376_ge_nodes"
	migration377PreviousUpSHA   = "0ad20b16426922d6431242432f2f849377f08a1ba877d5cb789549c45844f36b"
	migration377PreviousDownSHA = "226f0e4861f84b421af0549207d09998e888abfd6e0dfe4eb5d9f4298fba4ae9"
	migration377UpSHA           = "ad1e06fdd563af1c6a0aff2f2f168d2131662bb62104a6af4bba782fb88ebcf1"
	migration377DownSHA         = "60f1f4da452c625a07765a5fb88af4e2fe683d6f8e4a57aeaa14f24b0038fdbf"
)

func TestDDoSProtection377Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration377ID + ".up.sql", migration377UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration377Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration377Version-1),
			"migration_id='" + migration377PreviousID + "'", migration377PreviousUpSHA, migration377PreviousDownSHA,
			"ERRCODE='P3770'", "CREATE FUNCTION system_configuration_v2_ddos_protection_is_valid",
			"ARRAY['node_monitoring','ddos_protection']",
		}},
		{migration377ID + ".down.sql", migration377DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration377Version),
			"migration_id='" + migration377ID + "'", "ERRCODE='P3771'",
			"DROP FUNCTION system_configuration_v2_ddos_protection_is_valid",
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
