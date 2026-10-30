package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// (placeholder number). Every number the merge renumbering
// touches is here: the version, the previous head it guards on, and the
// script checksums.
const (
	l4TOAVersion         = 316
	l4TOAPreviousVersion = 315
	l4TOAID              = "316_l4_toa"
	l4TOAPreviousID      = "315_ip_intel_library"
	l4TOAPreviousUpSHA   = "5632dfd2da07bdf177f02996c1b319075aa6c781c1a745b3bf4e2814b9b84755"
	l4TOAPreviousDownSH  = "b2e8ac45c3b828a7ba13f20b18340cfe59cc8b511da8beea43e4efa8357399c8"
	l4TOAUpSHA           = "18e4b00b627ff5367dfcfbcff59af5b8dae21dbcd26820eaa53c94c103bc87e3"
	l4TOADownSHA         = "3afc4e8e5fdee2bc7953d7659e1df6526adfcb4e1645184dc691600298123ec0"
)

func TestL4TOA316Contract(t *testing.T) {
	previous := l4TOAPreviousVersion
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{l4TOAID + ".up.sql", l4TOAUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + l4TOAPreviousID + "'",
			"checksum_sha256='" + l4TOAPreviousUpSHA + "'",
			"down_checksum_sha256='" + l4TOAPreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", l4TOAVersion),
			"NOT toa OR (protocol = 'tcp' AND site_id IS NOT NULL AND",
			"validate_l4_runtime_spec_300(target_stream_id,target_scope_id,target_site_id,runtime_spec-'toa')",
			"l4_publish_intents_runtime_spec_316",
		}},
		{l4TOAID + ".down.sql", l4TOADownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", l4TOAVersion),
			"migration_id='" + l4TOAID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", l4TOAVersion), fmt.Sprintf("ERRCODE='P%d2'", l4TOAVersion),
			"l4_publish_intents_runtime_spec_300",
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
