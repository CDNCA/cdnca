package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Every number the merge renumbering touches is here.
const (
	l4SessionLogVersion        = 328
	l4SessionLogID             = "328_l4_session_log"
	l4SessionLogPreviousID     = "327_cc_site_settings"
	l4SessionLogPreviousUpSHA  = "ea7159112cd8cd207b0d57a86de28f82c65a4b25bf13a450a340951b690c4447"
	l4SessionLogPreviousDownSH = "3aa5c37c1bd32cc711dc981f8c26cbc2f6183a50ec17a674fb385221075f6e16"
	l4SessionLogUpSHA          = "88f45b5711dba3c53c8c1c0a0fdf75cde7f1fc036e3bdc4a38456854df9e9fb1"
	l4SessionLogDownSHA        = "0a68e90db060befb2cc03aef8765a3bff4f95a8027352a4ee87b649eb7ec1589"
)

func TestL4SessionLog328Contract(t *testing.T) {
	previous := l4SessionLogVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{l4SessionLogID + ".up.sql", l4SessionLogUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + l4SessionLogPreviousID + "'",
			"checksum_sha256='" + l4SessionLogPreviousUpSHA + "'",
			"down_checksum_sha256='" + l4SessionLogPreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", l4SessionLogVersion),
			"session_log_enabled boolean NOT NULL DEFAULT false",
			"validate_l4_runtime_spec_316(target_stream_id,target_scope_id,target_site_id,runtime_spec-'session_log')",
			"l4_publish_intents_runtime_spec_328",
		}},
		{l4SessionLogID + ".down.sql", l4SessionLogDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", l4SessionLogVersion),
			"migration_id='" + l4SessionLogID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", l4SessionLogVersion), fmt.Sprintf("ERRCODE='P%d2'", l4SessionLogVersion),
			"l4_publish_intents_runtime_spec_316",
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
