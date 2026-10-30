package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 505: a stream's own CNAME allocation. 505
// follows L2 topology config 504; the guard pins 504 — renumber/repin at merge
// (shift-migrations.py + cascade-all.sh).
const (
	migration505Version         = 505
	migration505PreviousVersion = 504
	migration505ID              = "505_cname_stream_owner"
	migration505PreviousID      = migration504ID
	migration505PreviousUpSHA   = migration504UpSHA
	migration505PreviousDownSHA = migration504DownSHA
	migration505UpSHA           = "2b2c88581e062c9c5e749bd563f52c8cc25ddf64a047e769e68cfa3a1d12c5bd"
	migration505DownSHA         = "ca277385a1be765a1ba82cf7b12fea49d1ec533add60f0da64a3cc726dfce64e"
)

func TestCNAMEStreamOwner505Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration505ID + ".up.sql", migration505UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration505PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration505PreviousVersion),
			"migration_id='" + migration505PreviousID + "'", migration505PreviousUpSHA, migration505PreviousDownSHA,
			"ERRCODE='P5050'", "ADD COLUMN stream_owner_id uuid", "cname_allocations_stream_owner_505_uidx",
			"cname_allocations_owner_505_check", "CREATE TABLE cname_stream_bindings", "CREATE TABLE cname_stream_intents",
			"CREATE OR REPLACE FUNCTION validate_cname_allocation_113()",
			"CREATE OR REPLACE FUNCTION validate_cname_allocation_request_113()",
			"CREATE OR REPLACE FUNCTION validate_cname_platform_intent_262()",
			"CREATE OR REPLACE FUNCTION cname_claim_released_476(retired_claim_id uuid)",
			"'stream_deleted','stream_released'",
		}},
		{migration505ID + ".down.sql", migration505DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration505Version),
			"migration_id='" + migration505ID + "'", "ERRCODE='P5054'", "ERRCODE='P5055'",
			"DROP TABLE cname_stream_bindings", "DROP COLUMN stream_owner_id",
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
