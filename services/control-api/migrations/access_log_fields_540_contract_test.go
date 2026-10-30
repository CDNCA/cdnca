package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 540 (fix-logfields2: system configuration category
// access_log_fields). Its predecessor is 539 (ticket_soft_delete),
// pinned by checksum; checksums in the guard.
const (
	migration540ID      = "540_access_log_fields"
	migration540UpSHA   = "a14454cda5578790e3e260bd9eb2a3ca929245ec0c2edc3210b2d247c95bc7df"
	migration540DownSHA = "bacd52f5fd4ed3be005fe64a10990c2fb806fd5c5501f5de7339baddf98fed85"
)

func TestAccessLogFields540Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration540ID + ".up.sql", migration540UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 539", "(SELECT max(version) FROM schema_migrations) <> 539",
			"migration_id='539_ticket_soft_delete'", "2b6a4e41a1b492d9bedec9a13888557279f1aad806745b2c2f7923ce8863a974",
			"380532e653efe7b0cc0dbb71e07c681ddb472e8f200f300669a7bd036015fbdf", "ERRCODE='P5400'",
			"CREATE FUNCTION system_configuration_v2_access_log_fields_is_valid",
			"ARRAY['node_monitoring','ddos_protection','access_log_fields']",
		}},
		{migration540ID + ".down.sql", migration540DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 540", "migration_id='" + migration540ID + "'", "ERRCODE='P5401'",
			"ARRAY['node_monitoring','ddos_protection']", "DROP FUNCTION system_configuration_v2_access_log_fields_is_valid",
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
	// The catalog is checked against edgeconfig by the latest migration
	// that defines it (542).
}
