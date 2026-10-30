package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 363 (PA-14 rule pack content protection) is a placeholder
// number (guard on the 362 head; 361-363 are taken by pa20-events): the merge
// renumbers it after the head it lands on. Everything that
// changes with the renumbering is here.
const (
	migration363Version         = 363
	migration363PreviousVersion = 362
	migration363ID              = "363_rule_pack_protection"
	migration363PreviousID      = "362_aggregated_edge_import"
	migration363PreviousUpSHA   = "25f0e327bf06645a658a6bb06ef880fa579bf619b08a376208106334002af3cd"
	migration363PreviousDownSHA = "c4aa6d3607c8f0d7fc85ec3f4650b48e40e053c0bdf50425dccef9100419db6c"
	migration363UpSHA           = "bcd1e0d6d738e783d8ed0690f8ffd9adb4f07674d888e56e06047cb1ba4482fd"
	migration363DownSHA         = "b0491dacc3291c7dbc954dadbfdd366ab30a213133c5f6a7b5fe51290d74db3e"
)

func TestRulePackProtection363Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration363ID + ".up.sql", migration363UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration363PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration363PreviousVersion),
			"migration_id='" + migration363PreviousID + "'", migration363PreviousUpSHA, migration363PreviousDownSHA,
			"ERRCODE='P3630'", "CREATE TABLE node_rule_pack_keys", "ADD COLUMN wrapped_key",
			"ADD COLUMN current_wrapped_key", "REFERENCES node_artifact_encryption_keys(id, node_id) ON DELETE CASCADE",
		}},
		{migration363ID + ".down.sql", migration363DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration363Version),
			"migration_id='" + migration363ID + "'", "ERRCODE='P3639'", "ERRCODE='P3631'", "DROP TABLE node_rule_pack_keys",
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
		if strings.Contains(string(raw), "CASCADE;") && !strings.Contains(string(raw), "ON DELETE CASCADE") {
			t.Errorf("%s uses CASCADE drops", script.name)
		}
	}
	// The control plane never stores a decrypted pack: no column for one.
	up, _ := FS.ReadFile(migration363ID + ".up.sql")
	if strings.Contains(string(up), "plaintext") || strings.Contains(string(up), "content_key ") {
		t.Error("363 must not add a plaintext or content key column")
	}
}
